strip_pdf() {
 echo "Original Metadata for $1"
 exiftool $1

 echo "Removing Metadata...."
 echo ""
 qpdf --linearize $1 striped1-$1
 exiftool -all:all= striped1-$1
 qpdf --linearize striped1-$1 striped2-$1
 rm striped1-$1
 rm striped1-$1_original

 echo "New Metadata for striped2-$1"
 exiftool striped2-$1
 echo ""

 echo "Securing striped2-$1...."
 password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 40 | head -n 1)
 echo "Password will be: $password"
 echo ""
 qpdf --linearize --encrypt "" $password 128 --print=full --modify=none --extract=n --use-aes=y -- striped2-$1 striped-$1
 rm striped2-$1

 echo "Final status of striped-$1"
 pdfinfo striped-$1
}
