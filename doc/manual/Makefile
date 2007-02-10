

html: manual.xml
	docbook2html -c /usr/pkg/etc/sgml/catalog --nochunks manual.xml

dvi: manual.xml
	docbook2dvi manual.xml

pdf: manual.xml
	docbook2pdf manual.xml

valid: manual.xml
	nsgmls -sv -c /etc/xml/catalog /usr/share/sgml/xml.dcl manual.xml
