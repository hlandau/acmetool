#!/bin/sh
set -e; exec guile --fresh-auto-compile --no-auto-compile -L "$(dirname "$0")/scheme-lib" -s "$0" "$@" #!#
;; vim: filetype=scheme fdm=marker
(define-module (website))
(use-modules (ice-9 match) (ice-9 ftw) (sxml2))

;; Main Document                                                            {{{1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-public ns-xhtml "http://www.w3.org/1999/xhtml")

(define _acmetool "acmetool")

(define* (page-layout #:key
                      (title _acmetool)
                      (logo #f)
                      (body '()))
  `(*TOP*
     (html (@ (@ (*NAMESPACES* (*IMPLICIT* ,ns-xhtml    *IMPLICIT*)))
              (lang en) (xml:lang en))
           (head
             (meta (@ (http-equiv "Content-Type") (content "application/xhtml+xml; charset=utf-8")))
             (meta (@ (http-equiv "X-UA-Compatible") (content "IE=edge")))
             (meta (@ (name "viewport") (content "width=device-width,initial-scale=1")))
             (title ,(if logo title (string-append title " — acmetool")))
             (link (@ (rel stylesheet) (href "dedoc-website.css"))))
           (body
             (div (@ (class main-wrap))
               (nav (@ (class top-nav))
                 (ul (@ (class rhs))
                   (li (a (@ (href "https://www.devever.net/~hl/") (class cross-slash-icon-link)) (span) "Hugo Landau")))
                 (ul (@ (class lhs))
                   (li (a (@ (href ".") (class logotext)) ,_acmetool))
                   (li (a (@ (href ".")) "Home"))
                   (li (a (@ (href "download")) "Download"))
                   (li (a (@ (href "doc")) "Documentation"))
                   (li (a (@ (href "https://github.com/hlandau/acmetool")) "GitHub"))))
               (div (@ (class swipe-reminder) (hidden ""))
                    (p "⇒ Swipe right for navigation ⇒"))
               ,(if logo `(div (@ (class prealign))
                    (h1 (@ (class logo-img))
                        (img (@ (alt "acmetool") (src "https://hlandau.github.io/acmetool/img/acmetool-logo-black.png"))))) "")
               (main
                 (article (@ (class has-logo))
                    ,(if (not logo) `(h1 ,title) "")
                    ,@body))

               (footer (ul
                  ,(let ((git-short (getenv "GITINFO_SHORT"))
                        (git-long (getenv "GITINFO_LONG")))
                     (if git-short `(li (@ (title ,(or git-long ""))) ,git-short) ""))
                  (li (@ (class nodot))
                      (a (@ (class cross-slash-icon-link)
                            (href "https://www.devever.net/~hl/")) (span) "Hugo Landau")))))))))

(define (intro)
  `(
    (p "acmetool is an easy-to-use command line tool for automatically acquiring certificates from ACME servers (such as Let's Encrypt). Designed to flexibly integrate into your webserver setup to enable automatic verification. Unlike the official Let's Encrypt client, this doesn't modify your web server configuration.")))

(define-public (web-index)
  (let ((title (string-append "acmetool")))
    (page-layout #:title title #:logo #t #:body (intro))))

(define (download)
  `(
    (p "foo")))

(define-public (web-download)
    (page-layout #:title "Download" #:body (download)))

(define (doc)
  `(
    (p "doc")))

(define-public (web-doc)
    (page-layout #:title "Documentation" #:body (doc)))

;; Generation and Output                                                    {{{1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define (pages)
  `((index . ,(web-index))
    (download . ,(web-download))
    (doc . ,(web-doc))))

(define (write-page slug sxml)
  (call-with-output-file (format #f "build/out/~s.xhtml" slug) (lambda (output-port)
    (with-output-to-port output-port (lambda () (sxml->xml sxml))))))

(define (write-all-pages)
  (for-each (lambda (page) (write-page (car page) (cdr page))) (pages)))

;; If this file is being executed directly, generate the pages.
(when (eq? autoloads-in-progress '())
  (write-all-pages))
