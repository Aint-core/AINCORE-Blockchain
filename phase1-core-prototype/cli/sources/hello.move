module 0x872aa1448f18746d93f590f9508135b8::hello {
    use std::string;

    struct Message has key, drop {
        text: string::String
    }

    public fun get_message(): string::String {
        string::utf8(b"Hello, AINCORE!")
    }
}
