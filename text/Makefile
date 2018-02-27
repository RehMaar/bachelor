PDFDIR=pdf
SRCDIR=src

LATEX=xelatex
FLAGS=-output-directory $(PDFDIR)


all:
	$(LATEX) $(FLAGS) $(SRCDIR)/main.tex

pdf:
	zathura $(PDFDIR)/main.pdf

.PHONY: pdf
