<!DOCTYPE style-sheet PUBLIC "-//James Clark//DTD DSSSL Style Sheet//EN" [
<!ENTITY % html "IGNORE">
<![%html;[
<!ENTITY % print "IGNORE">
<!ENTITY docbook.dsl PUBLIC "-//Norman Walsh//DOCUMENT DocBook HTML Stylesheet//EN" CDATA dsssl>
]]>
<!ENTITY % print "INCLUDE">
<![%print;[
<!ENTITY docbook.dsl PUBLIC "-//Norman Walsh//DOCUMENT DocBook Print Stylesheet//EN" CDATA dsssl>
]]>
]>
<style-sheet>
<style-specification id="print" use="docbook">
<style-specification-body> 

;; customize the print stylesheet
(define %graphic-default-extension% 
  "ps")

</style-specification-body>
</style-specification>
<style-specification id="html" use="docbook">
<style-specification-body> 

;; customize the html stylesheet

(define %root-filename%
  ;; The filename of the root HTML document (e.g, "index").
  "index")

(define %html-ext%
  ".html")

(define %shade-verbatim%
  #t)

(define %use-id-as-filename%
  ;; Use ID attributes as name for component HTML files?
  #t)

;; Add to the body tag.
;(define %body-attr% 
;  (list
;   (list "BGCOLOR" "#EEEEEE")
;   (list "TEXT" "#000000")
;   (list "LINK" "#0000FF")
;   (list "VLINK" "#840084")
;   (list "ALINK" "#0000FF")))

(define %stylesheet%
  "manual.css")

(define %stylesheet-type%
  "text/css")

(define (toc-depth nd)
  ;; more depth (2 levels) to toc; instead of flat hierarchy
  2)

;; Don't produce lists of anything other than headings.
(define ($generate-book-lot-list$)
  ;; Which Lists of Titles should be produced for Books?
  (list))

(define %graphic-default-extension% 
  "png")

;; Insert the sourceforge graphic at the end of each page.
(define ($html-body-end$)
  (make sequence
    (make formatting-instruction data: "&#60div ")
    (literal "class=\"boxed\" style=\"text-align: center;\"")
    (make formatting-instruction data: ">gtk-gnutella development ")
    (literal "hosted by")
    (make formatting-instruction data: "&#60a class=")
    (literal "\"image\" href=\"https://sourceforge.net\"")
    (make formatting-instruction data: ">&#60img ")
    (literal "style=\"vertical-align:middle;\" ")
    (literal "src=\"https://sourceforge.net/sflogo.php")
    (literal "?group_id=4467")
    (make formatting-instruction data: "&#38amp;type=1\" ")
    (literal "alt=\"SourceForge.net Logo\" width=\"88\" height=\"31\"/")
    (make formatting-instruction data: ">&#60/a>")
    (make formatting-instruction data: "&#60/div>")))

</style-specification-body>
</style-specification>
<external-specification id="docbook" document="docbook.dsl">
</style-sheet>
