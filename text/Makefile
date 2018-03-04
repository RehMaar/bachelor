PDFDIR=pdf
SRCDIR=src

LATEX=xelatex
FLAGS=-output-directory $(PDFDIR) -output-driver=xdvipdfmx


all:
	$(LATEX) $(FLAGS) $(SRCDIR)/main.tex

pdf:
	zathura $(PDFDIR)/main.pdf

.PHONY: pdf
