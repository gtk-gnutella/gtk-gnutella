

html: manual.xml
	docbook2html --nochunks manual.xml

pdf: manual.xml
	docbook2pdf manual.xml

valid: manual.xml
	nsgmls -sv -c /etc/xml/catalog /usr/share/sgml/xml.dcl manual.xml
