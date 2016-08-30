;;; pcap-mode.el --- Major mode for working with PCAP files

;; Author: Aaron Conole <aconole@bytheb.org>
;; Created: 2016-08-16
;; Edited: 2016-08-29
;; Version: 0.2
;; Keywords: pcap, packets, tcpdump, wireshark, tshark
;; Repository:
;; Package-Requires: ((emacs "24.3"))

;; This file is not part of GNU Emacs.

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 2 of the License, or (at
;; your option) any later version.

;; This program is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANY; without even the implied warranty of MERCHANTABILITY
;; or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
;; for more details.

;; You should have received a copy of the GNU General Public License along
;; with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:
;; This is a pcap viewing mode.  It uses tshark underneath to parse and
;; display sections of the packets.

;;; TODO:
;; * smart quoting of the tshark command line arguments.

;;; Change Log:
;; * 2016-08-16 (aconole) Initial Version
;; * 2016-08-17 (syohex) Fix up the meta comments in the package
;; * 2016-08-18 (glallen01) Added pcap-list-tcp-conversations and
;;                          pcap-follow-tcp-stream
;;              (aconole) Modify pcap-view-pkt-contents to follow tcp-stream
;;                        in conversation mode
;; * 2016-08-20 (aconole) Allow root users to interact with the tcp
;;                        conversation following code.
;; * 2016-08-22 (aconole) Allow pcap-mode to start a capture when tramp mode
;;                        strings are specified.
;; * 2016-08-24 (aconole) Corrected a tramp-mode bug.
;;                        Added autoload hints
;;                        prefixed all of the pcap-mode variables with
;;                           `pcap-mode--`
;; * 2016-08-29 (aconole) Renamed all pcap-mode variables (again)
;;                        Autoload the alist call
;;                        checkdoc
;; * 2016-08-29 (aconole) Shell-quote the file and interface names
;;; Code:

(defgroup pcap-mode nil "Major mode for viewing pcap files"
  :group 'data)

;;;###autoload
(defcustom pcap-mode-tshark-executable (executable-find "tshark")
  "Path to the tshark executable."
  :type 'string
  :group 'pcap-mode)

;;;###autoload
(defcustom pcap-mode-reload-pcap-when-filter-changes t
  "Whether to reload the pcap file after changing the filter."
  :type 'boolean
  :group 'pcap-mode)

;;;###autoload
(defcustom pcap-mode-tshark-filter ""
  "Filter to apply to tshark invocations."
  :type 'string)

;;;###autoload
(defcustom pcap-mode-tshark-single-packet-filter "-V -Y"
  "Filter to apply when displaying individual packets."
  :type 'string)

(defvar pcap-mode--tshark-filter-history nil
  "Stores the history for tshark display pcap filters.")
(defvar pcap-mode--tshark-single-packet-filter-history nil
  "Stores the history for tshark display single-packet filters.")
(defvar pcap-mode--capture-interface-history nil
  "Stores the interfaces used to capture pcap data.")
(defvar pcap-mode--capture-stop-condition-history nil
  "Stop condition history.")
(defvar pcap-mode--capturing-filters-history nil
  "Stores the history of capture filters.")

;;;###autoload
(defvar pcap-mode-hook nil
  "Hook list run when a pcap file is opened.")

;;;###autoload
(defvar pcap-mode-reloaded-hook nil
  "Hook list run whenever the pcap file is loaded or reloaded.")

;;;###autoload
(defvar pcap-mode-quit-hook nil
  "Hook list run when a pcap file is closed.")

(defvar pcap-mode--pcap-packet-cleanup-list)

;;;###autoload
(defvar pcap-mode-map
  (let ((kmap (make-keymap)))
    (define-key kmap (kbd "<return>") 'pcap-mode-view-pkt-contents)
    (define-key kmap (kbd "t") 'pcap-mode-toggle-tcp-conversation-view)
    (define-key kmap (kbd "f") 'pcap-mode-set-tshark-filter)
    (define-key kmap (kbd "\C-u f")
      'pcap-mode-set-tshark-single-packet-filter)
    (define-key kmap (kbd "s") 'pcap-mode-set-tshark-single-packet-filter)
    (define-key kmap (kbd "r") 'pcap-mode-reload-file)
    (define-key kmap (kbd "\C-c \C-d") (lambda () (interactive)
                                        (message "tshark filter \"%s\""
                                                 pcap-mode-tshark-filter)))
    (define-key kmap (kbd "q") (lambda () (interactive) (kill-buffer)))
    kmap)
  "Keymap for pcap major mode.")

(defun pcap-mode--viewing-tcp-conversations ()
  "Returns t when viewing TCP conversations in the current buffer."
  (let ((line2 (save-excursion (goto-char (point-min))
                               (forward-line 1) (beginning-of-line)
                               (buffer-substring-no-properties
                                (line-beginning-position)
                                (line-end-position))))
        (line3 (save-excursion (goto-char (point-min))
                               (forward-line 2) (beginning-of-line)
                               (buffer-substring-no-properties
                                (line-beginning-position)
                                (line-end-position)))))
    (if (or (string= line2 "TCP Conversations")
            (string= line3 "TCP Conversations"))
        t
      nil)))

(defun pcap-mode-list-tcp-conversations ()
  "List the tcp conversations within a PCAP."
  (interactive)
  (pcap-mode-set-tshark-filter "-n -q -z conv,tcp"))

(defun pcap-mode-toggle-tcp-conversation-view ()
  "List the tcp conversations within a PCAP, or clear the list."
  (interactive)
  (if (pcap-mode--viewing-tcp-conversations)
      (pcap-mode-set-tshark-filter "")
    (pcap-mode-list-tcp-conversations)))

(defun pcap-mode-follow-tcp-stream ()
  "From the list of tcp conversations, set the output filter to follow the stream.
Requires running pcap-list-tcp-conversations first."
  (interactive)
  (let* ((line (buffer-substring-no-properties
              (line-beginning-position)
              (line-end-position)))
         (connection ; (sip, sport, dip, dport)
          (append (split-string (car (split-string line)) ":")
                  (split-string (car (cddr (split-string line))) ":"))))
         (pcap-mode-set-tshark-filter
            (replace-regexp-in-string "== " "=="
                                    (mapconcat 'identity
                                               (list
                                                "-Y \""
                                                "ip.addr=="
                                                (car connection)
                                                "&& tcp.port=="
                                                (car (cdr connection))
                                                "&& ip.addr=="
                                                (car (cddr connection))
                                                "&& tcp.port=="
                                                (car (cdr (cddr connection)))
                                                "\"")
                                               " ")))))

(defun pcap-mode--get-tshark-command (filename filters &optional
                                               capture-interface)
  "Returns the string to pass to a shell command.
This will pass
FILENAME either as a read interface or a write interface, based on
the value of CAPTURE-INTERFACE.  The value of FILTERS will not be
escaped to allow passing important filtering arguments (such as -Y)."
  (require 'tramp)
  (let ((real-filename (if (tramp-tramp-file-p filename)
                           (elt (tramp-dissect-file-name filename) 3)
                           filename)))
    (let ((input-flag (if capture-interface
                          (format "-i %s -w %s" (shell-quote-argument capture-interface)
                                  (shell-quote-argument real-filename))
                        (format "-r %s" (shell-quote-argument real-filename))))
          (tshark-name (if (tramp-tramp-file-p filename)
                           (format "sudo %s" pcap-mode-tshark-executable)
                         pcap-mode-tshark-executable)))
      (format "%s %s %s" tshark-name input-flag filters))))

(defun pcap-mode--packet-number-from-tshark-list ()
  "Return the line number of a packet."
  (save-excursion
    (beginning-of-line)
    (skip-chars-forward " \r\n\t")
    (thing-at-point 'word)))

(defun pcap-mode-view-pkt-contents ()
  "View a specific packet in the current packet capture.
Invokes tshark  adding the `frame.number==` display filter."
  (interactive)
  (if (pcap-mode--viewing-tcp-conversations)
      (pcap-mode-follow-tcp-stream)
    (let ((packet-number (pcap-mode--packet-number-from-tshark-list)))
      (let ((cmd (pcap-mode--get-tshark-command (buffer-file-name)
                                                (format "%s frame.number==%s"
                                                        pcap-mode-tshark-single-packet-filter
                                                        packet-number)))
            (temp-buffer-name (format "*Packet <%s from %s>*" packet-number
                                      (buffer-file-name))))
        (get-buffer-create temp-buffer-name)
        (add-to-list 'pcap-mode--pcap-packet-cleanup-list temp-buffer-name)
        (let ((message-log-max nil))
          (shell-command cmd temp-buffer-name))
        (switch-to-buffer-other-window temp-buffer-name)
        (special-mode)))))

(defun pcap-mode--get-tshark-for-file (filename filters buffer &optional
                                                interface)
  "Executes the tshark executable with FILENAME and FILTERS as arguments,
storing the output in buffer.  If the `pcap-mode-tshark-executable` is not
found, set the buffer to an error message."
  (if pcap-mode-tshark-executable
      (shell-command (pcap-mode--get-tshark-command filename filters interface)
                     buffer)
    (let ((oldbuf (current-buffer)))
      (switch-to-buffer buffer)
      (setf (buffer-string) "**ERROR: tshark executable not found")
      (switch-to-buffer oldbuf))))

(defun pcap-mode-capture-file (filename buffer)
  "Start capturing to FILENAME and then reloads in BUFFER.
The capture will prompt for a timeout, an interface, and a capture filter."
  (let ((interface (read-string "Interface? " '("any" . 1) nil
                                pcap-mode--capture-interface-history))
        (capture-timeout (read-string
                          "Stop Condition (duration in seconds)? "
                          '("10" . 1) nil
                          pcap-mode--capture-stop-condition-history))
        (capture-string (read-string "Capture string? " '("-s 65535 " . 1)
                                     nil pcap-mode--capturing-filters-history)))
    (if (not capture-timeout)
        (message "**ERROR: Need a capture timeout")
      (progn
        (message "Capturing [%s]" (format "%s" (pcap-mode--get-tshark-command
                                                filename
                                                (format "-a duration:%s %s"
                                                        capture-timeout
                                                        capture-string)
                                                interface)
                                          ))
        (pcap-mode--get-tshark-for-file filename (format "-a duration:%s %s"
                                                         capture-timeout
                                                         capture-string)
                                        (current-buffer)
                                        interface)
        (if (file-exists-p (buffer-file-name))
            (progn
              (revert-buffer)
              (pcap-mode-reload-file))
          (setf (buffer-string)
                "*** No file generated - can you capture?"))))))

(defun pcap-mode-reload-file ()
  "Reloads the current pcap file into the buffer with
`pcap-mode-tshark-executable` and the current buffer filters."
  (interactive)
  (setq inhibit-read-only t)
  (setf (buffer-string) "")
  (mapc 'kill-buffer pcap-mode--pcap-packet-cleanup-list)
  (setq pcap-mode--pcap-packet-cleanup-list '())
  (if (file-exists-p (buffer-file-name))
      (pcap-mode--get-tshark-for-file (buffer-file-name) pcap-mode-tshark-filter
                                      (current-buffer))
    (let ((should-create-pcap (y-or-n-p
                               (format
                                "PCAP File (%s) doesn't exist.  Create? "
                                (buffer-file-name)))))
      (if should-create-pcap
          (pcap-mode-capture-file (buffer-file-name) (current-buffer))
        (setf (buffer-string) "*** PCAP file does not exist"))))
  (set-buffer-modified-p nil)
  (setq inhibit-read-only nil)
  (read-only-mode)
  (run-hooks 'pcap-mode-reloaded-hook))

(defun pcap-mode-set-tshark-single-packet-filter (filter-value)
  "Set the tshark filter for single packets.
Argument FILTER-VALUE corresponds to the exact set of filters passed to `pcap-mode-tshark-executable`."
  (interactive (list (read-from-minibuffer "TShark Single Packet Filter: "
                                           pcap-mode-tshark-single-packet-filter
                                           nil nil
                                           '(pcap-mode--tshark-single-packet-filter-history . 1))))
  (setq-local pcap-mode-tshark-single-packet-filter filter-value))

(defun pcap-mode-set-tshark-filter (filter-value)
  "Set the tshark filters.
If `pcap-mode-reload-pcap-when-filter-changes` is
true, automatically invokes the reload function.
Argument FILTER-VALUE corresponds to the exact set of filters passed to `pcap-mode-tshark-executable`."
  (interactive (list (read-from-minibuffer "TShark Filter: "
                                           pcap-mode-tshark-filter nil nil
                                           '(pcap-mode--tshark-filter-history . 1))))
  (setq-local pcap-mode-tshark-filter filter-value)
  (if pcap-mode-reload-pcap-when-filter-changes
      (pcap-mode-reload-file)))

(defun pcap-mode--pcap-mode-cleanup ()
  "Cleanup function run whenever a pcap buffer is closed."
  (run-hooks 'pcap-mode-quit-hook)
  (mapc 'kill-buffer pcap-mode--pcap-packet-cleanup-list))

;;;###autoload
(define-derived-mode pcap-mode special-mode "PCAP-Mode"
  "Major mode for viewing pcap files."
  (make-local-variable 'pcap-mode-tshark-filter)
  (make-local-variable 'pcap-mode-tshark-single-packet-filter)
  (make-local-variable 'pcap-mode--pcap-packet-cleanup-list)
  (setq pcap-mode--pcap-packet-cleanup-list '())
  (pcap-mode-reload-file)
  (read-only-mode)
  (add-hook 'kill-buffer-hook 'pcap-mode--pcap-mode-cleanup nil t))

;;;###autoload
(add-to-list 'auto-mode-alist '("\\.pcap\\'" . pcap-mode))
(provide 'pcap-mode)
;;; pcap-mode.el ends here
