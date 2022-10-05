#[cfg(test)]
mod fuzz_tests {

    use crate::explore_me::explore_me;

    #[test]
    fn my_fuzz_test() {     // <- pass FuzzedDataProvider
        let a = 397652;     // replace with FuzzedDataProvider.consume_int()
        let b = 3082562284; // replace with FuzzedDataProvider.consume_int()

        let c = "FUZZING";  // replace with FuzzedDataProvider.consume_remaining_as_string()

        explore_me(a, b, c);
    }
}
