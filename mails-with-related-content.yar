rule mails_with_related_content
{
    meta:
        description = "Yara rule to find emails submitted that have #KEYWORD in their contents"
        author = "Martin Jaan Leesment"
        file_type = "eml"
    strings:
        //From LaikaBOSS
        $from = "From "
        $received = "\x0aReceived:"
        $return = "x0aReturn-Path:"
        //Keyword
        $a = "@testdomain.com"
        $b = "@testdomain.eu"
    condition:
        //From LaikaBOSS + keywords
        (($from at 0 and ($a or $b)) or ($received in (0 .. 2048) and ($a or $b))
          or ($return in (0 .. 2048) and ($a or $b)))
}
