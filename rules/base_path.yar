rule Path {
    strings:
        $path = /([a-zA-Z]:\\|\\)?(([\w]{3,}|[\-\. ])+(\\?))+((\w+\.\w+)|(\w+))/ wide ascii
    condition:
        all of them
}