;;; pcap-mode.el --- Major mode for working with PCAP files

;; Author: Aaron Conole <aconole@bytheb.org>
;; Created: 2016-08-16
;; Edited: 2016-08-16
;; Version: 0.1
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
;; * Get a mechanism for expanding/collapsing the packet files

;;; Change Log:
;; * 2016-08-16 (aconole) Initial Version
;; * 2016-08-17 (syohex) Fix up the meta comments in the package
;; * 2016-08-18 (glallen01) Added pcap-list-tcp-conversations and
;;                          pcap-follow-tcp-stream
;;              (aconole) Modify pcap-view-pkt-contents to follow tcp-stream
;;                        in conversation mode

;;; Code:

(defgroup pcap-mode nil "Major mode for viewing pcap files")

(defcustom tshark-executable (executable-find "tshark")
  "Path to the tshark executable"
  :type 'string
  :group 'pcap-mode)

(defcustom reload-pcap-when-filter-changes t
  "Whether to reload the pcap file after changing the filter"
  :type 'boolean
  :group 'pcap-mode)

(defcustom tshark-filter ""
  "Filter to apply to tshark invocations"
  :type 'string)

(defcustom tshark-single-packet-filter "-V -Y"
  "Filter to apply when displaying individual packets"
  :type 'string)

(defvar tshark-filter-history nil
  "Stores the history for tshark display pcap filters")
(defvar tshark-single-packet-filter-history nil
  "Stores the history for tshark display single-packet filters")
(defvar pcap-reloaded-hook nil
  "Hook list run whenever the pcap file is loaded or reloaded")
(defvar pcap-mode-hook nil
  "Hook list run when a pcap file is opened")
(defvar pcap-mode-quit-hook nil
  "Hook list run when a pcap file is closed")

(defvar pcap-mode-map
  (let ((kmap (make-keymap)))
    (define-key kmap (kbd "<return>") 'pcap-view-pkt-contents)
    (define-key kmap (kbd "t") 'pcap-list-tcp-conversations)
    (define-key kmap (kbd "f") 'pcap-set-tshark-filter)
    (define-key kmap (kbd "\C-u f") 'pcap-set-tshark-single-packet-filter)
    (define-key kmap (kbd "s") 'pcap-set-tshark-single-packet-filter)
    (define-key kmap (kbd "r") 'pcap-reload-file)
    (define-key kmap (kbd "\C-c \C-d") (lambda () (interactive)
                                        (message "tshark filter \"%s\""
                                                 tshark-filter)))
    (define-key kmap (kbd "q") (lambda () (interactive) (kill-buffer)))
    kmap)
  "Keymap for pcap major mode")

(defun pcap-list-tcp-conversations ()
  "List the tcp conversations within a PCAP"
  (interactive)
  (pcap-set-tshark-filter "-n -q -z conv,tcp"))

(defun pcap-follow-tcp-stream ()
  "From the list of tcp conversations, set the output filter to
   follow the stream. (run pcap-list-tcp-conversations first)"
  (interactive)
  (let* ((line (buffer-substring-no-properties
              (line-beginning-position)
              (line-end-position)))
         (connection ; (sip, sport, dip, dport)
          (append (split-string (car (split-string line)) ":")
                  (split-string (car (cddr (split-string line))) ":"))))
         (pcap-set-tshark-filter
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

(defun get-tshark-command (filename filters)
  "Returns the string to pass to a shell command"
  (format "%s -r %s %s" tshark-executable filename filters))

(defun packet-number-from-tshark-list ()
  "Return the line number of a packet"
  (save-excursion
    (beginning-of-line)
    (skip-chars-forward " \r\n\t")
    (thing-at-point 'word)))

(defun pcap-view-pkt-contents ()
  "View a specific packet in the current packet capture.  Invokes tshark 
   adding the `frame.number==` display filter."
  (interactive)
  (let ((line2 (save-excursion (goto-line 2) (beginning-of-line)
                               (buffer-substring-no-properties
                                (line-beginning-position)
                                (line-end-position)))))
    (if (string= line2 "TCP Conversations")
        (pcap-follow-tcp-stream)
      (let ((packet-number (packet-number-from-tshark-list)))
        (let ((cmd (get-tshark-command (buffer-file-name)
                                       (format "%s frame.number==%s"
                                               tshark-single-packet-filter
                                               packet-number)))
              (temp-buffer-name (format "*Packet <%s from %s>*" packet-number
                                        (buffer-file-name))))
          (get-buffer-create temp-buffer-name)
          (add-to-list 'pcap-packet-cleanup-list temp-buffer-name)
          (let ((message-log-max nil))
            (shell-command cmd temp-buffer-name))
          (switch-to-buffer-other-window temp-buffer-name)
          (special-mode))))))

(defun get-tshark-for-file (filename filters buffer)
  "Executes the tshark executable with `filename` and `filters` as arguments,
   storing the output in buffer.  If the tshark-executable is not found, set
   the buffer to an error message."
  (if tshark-executable
      (shell-command (get-tshark-command filename filters) buffer)
    (let ((oldbuf (current-buffer)))
      (switch-to-buffer buffer)
      (setf (buffer-string) "**ERROR: tshark executable not found")
      (switch-to-buffer oldbuf))))

(defun pcap-reload-file ()
  "Reloads the current pcap file into the buffer with `tshark-executable`
   and the current buffer filters."
  (interactive)
  (setq inhibit-read-only t)
  (setf (buffer-string) "")
  (get-tshark-for-file (buffer-file-name) tshark-filter (current-buffer))
  (not-modified)
  (setq inhibit-read-only nil)
  (read-only-mode)
  (run-hooks 'pcap-reloaded-hook))

(defun pcap-set-tshark-single-packet-filter (filter-value)
  "Sets the tshark filter for single packets."
  (interactive (list (read-from-minibuffer "TShark Single Packet Filter: "
                                           tshark-single-packet-filter nil nil
                                           '(tshark-single-packet-filter-history . 1))))
  (setq-local tshark-single-packet-filter filter-value))

(defun pcap-set-tshark-filter (filter-value)
  "Sets the tshark filters.  If `reload-pcap-when-filter-changes` is true, 
   automatically invokes the reload function."
  (interactive (list (read-from-minibuffer "TShark Filter: "
                                           tshark-filter nil nil
                                           '(tshark-filter-history . 1))))
  (setq-local tshark-filter filter-value)
  (if reload-pcap-when-filter-changes
      (pcap-reload-file)))

(defun pcap-mode-cleanup ()
  "Cleanup function run whenever a pcap buffer is closed"
  (run-hooks 'pcap-mode-quit-hook)
  (mapc 'kill-buffer pcap-packet-cleanup-list))

(defun pcap-mode ()
  "Major mode for viewing pcap files"
  (interactive)
  (kill-all-local-variables)
  (make-variable-buffer-local 'tshark-filter)
  (make-variable-buffer-local 'tshark-single-packet-filter)
  (make-variable-buffer-local 'pcap-packet-cleanup-list)
  (use-local-map pcap-mode-map)
  (pcap-reload-file)
  (read-only-mode)
  (add-hook 'kill-buffer-hook 'pcap-mode-cleanup)
  (run-hooks 'pcap-mode-hook)
  (setq major-mode 'pcap-mode)
  (setq mode-name "PCAP-Mode"))

(add-to-list 'auto-mode-alist '("\\.pcap\\'" . pcap-mode))
(provide 'pcap-mode)
;;; pcap-mode.el ends here
