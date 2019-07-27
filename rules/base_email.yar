rule Email {
    strings:
        $email = /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/s fullword wide ascii

    condition:
        all of them
}