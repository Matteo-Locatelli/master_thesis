# UniBG LaTeX Thesis Template

A simple LaTeX template with the official [UniBG formatting rules](https://www.unibg.it/studiare/frequentare/laurearsi/frontespizi).

**Note**: this template is completely free, you can use it however you want.
However, you have to have a little sentence in your acknowledgements thanking
the *Seclab* if your thesis is with them (or *me* if not) for providing
this template.

## Requirements

The only real requirement if you want to use this offline is *LaTeX* (suggested TeX Live).
Check your OS installation method. For reference, this set of packages
could be considered a minimal working install (taken from the Arch Linux wiki):

- [`texlive-most`](https://archlinux.org/groups/x86_64/texlive-most/)
- [`biber`](https://archlinux.org/packages/community/any/biber/)

You can check for your OS what are the equivalent ones, or just use the full
installation.

As an extra, you can install [*latexmk*](https://miktex.org/packages/latexmk)
to make use of the `make` and `make watch` commands. Could come already installed
with some packages.

## Quick example

```latex
\documentclass[english,master]{unibg}

\title{A Seclab Thesis}
\subtitle{A Seclab Subtitle}
\advisor{Prof.~John Smith}

\department{Department of Engineering}
\course{Computer Science}
\class{LM-32}

\author{John Doe}
\studentid{177013}
\year{2021/2022}

\begin{document}
  \maketitle
\end{document}
```

See `main.tex` for the full setup.

## Usage

Main usage is done through `\documentclass[language,degreetype]{unibg}`. You can set:
- *Lanuage*, either `italian` (default) or `english`
- *Degree type*, either `master` (default) or `bachelor`

### Configuration

| Option        | Required | Description                                                                              |
| ------------- | -------- | ---------------------------------------------------------------------------------------- |
| `\title`      | ✔️        | The title of the thesis                                                                  |
| `\subtitle`   |          | The subtitle of the thesis (or a "less important" part of the title)                     |
| `\advisor`    | ✔️        | Your advisor (professor who followed you)                                                |
| `\coadvisor`  |          | Your coadvisor (if you don't know about this, then you don't need it)                    |
| `\department` | ✔️        | The [department](https://www.unibg.it/ateneo/organizzazione/dipartimenti) of your course |
| `\course`     | ✔️        | The official name of your course                                                         |
| `\class`      | ✔️        | The degree's class (check your course webpage)                                           |
| `\author`     | ✔️        | You (I hope)                                                                             |
| `\studentid`  | ✔️        | Your student number                                                                      |
| `\year`       | ✔️        | The academic year of your degree                                                         |

### Commands

| Command      | Description                | Options                                                                       |
| ------------ | -------------------------- | ----------------------------------------------------------------------------- |
| `\maketitle` | Creates the first page     | -                                                                             |
| `\emptypage` | Surprisingly, an empy page | -                                                                             |
| `\toc[opts]` | The table of contents      | Comma-separated list of zero or more among `figures`, `tables` and `listings` |

## Helpful questions

- *How to create a PDF?*

  Run `make` inside this folder.

- *How to have a live preview?*

  Run `make watch` inside this folder.
  Note that you have to configure `latexmk` in order to [support live updates](https://mg.readthedocs.io/latexmk.html#configuration-files).
  Also, this is known to not work with all viewers, especially not *Adobe Reader*.

- *I don't have make*/*I use Windows*

  Sorry about that. The files should be working without problems with any
  other editor (Overleaf, TeXstudio, etc). You may have to copy files around.

- *How to change language?*

  Write your desired language in the options of `\documentclass{unibg}`.

- *How does the table of contents work?*

  Just use `\toc`. Note that the table of contents kinda breaks the flow of opening chapters on a right page.
  So remember to check and add a `\emptypage` if necessary.

- *How can I show other tables of contents, like figures?*

  Use the optional argument to `\toc`. If you want to show all supported table of contents,
  do `\toc[figures,tables,listings]`. You can also mix and match how you prefer.
  The chapter/section/subsection table of contents will always be printed though.
