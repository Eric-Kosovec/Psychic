rule URL {
    strings:
        $url = /https?:\/\/([\w\.-]+)([\/\w \.-]*)|www.([\/\w \.-]*)/ wide ascii
    condition:
        all of them
}