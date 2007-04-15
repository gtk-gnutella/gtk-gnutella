# Our primary source will be the png files.
IMGS = search-stats.png search-monitor.png \
 no_firewall.png         firewall.png      \
 leaf.png                smallserver.png

IMGS_SCALE =                              \
 downloads.png       gtkg-diagram.png     \
 gnet.png            gnet-stats.png       \
 host-cache.png      upload-history.png   \
 search.png          uploads.png          \
 preferences.png     preferences-upload.png

# Create a list of postscript files.  Needed to produce dvi and pdf
# output.
IMAGE_SCALE = $(addprefix images/, $(addsuffix .ps, $(basename $(IMGS_SCALE))))
IMAGE_LIST  = $(addprefix images/, $(addsuffix .ps, $(basename $(IMGS))))

all: manual.html manual.pdf

# docbook2html --dsl gtk-gnutella.dsl#html manual.xml

# The xml will reference the postscript images.  The html output needs
# to reference something that web browsers understand.
manual.html: manual.xml
	docbook2html --nochunks manual.xml
	sed -i -e s/\\\.ps/\\\.png/g manual.html

# docbook2dvi seems to generate many "errors".  However, output is
# generated.
manual.dvi: manual.xml $(IMAGE_LIST) $(IMAGE_SCALE)
	- docbook2dvi manual.xml
	if [ -e manual.dvi ]; then echo "ok"; else exit -1; fi

# Generate a TeX file, only use-able by [pdf]jadetex.
manual.tex: manual.xml
	docbook2tex manual.xml

# Alternatives create a pdf from the dvi file.
# eg, dvipdf dvipdfm
#
# docbook2pdf creates unreadable fonts on my system.  Perhaps because
# some fonts are not installed.
#
manual.pdf: manual.dvi
	dvipdfm manual.dvi

# Make a plain text file.
manual.txt: manual.html
	lynx  -dump  -nolist  manual.html > manual.txt

# Check the validity of the xml.
valid: manual.xml
	nsgmls -sv -c /etc/sgml/catalog /usr/share/sgml/xml.dcl manual.xml

# Remove generated files (not images).
clean:
	- @rm manual.dvi manual.log manual.pdf manual.aux  2> /dev/null
	- @rm manual.out manual.txt manual.tex manual.html 2> /dev/null

# Create postscript images from the PNGs.
$(IMAGE_SCALE) : %.ps : %.png
	pngtopnm -mix -background white $< | pnmtops -noturn  -nocenter -nosetpage -imagewidth 6.5 > $@

$(IMAGE_LIST) :  %.ps : %.png
	pngtopnm -mix -background white $< | pnmtops -noturn -nocenter -nosetpage > $@


