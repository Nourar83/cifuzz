pub fn explore_me(a: u32, b: u32, c: &str) {
    println!("a: {}, b: {}, c: {}", a, b, c);

    if a >= 20000 {
        println!("branch 1");

        if b >= 2000000 {
            println!("branch 2");

            if b - a > 100000 {
                println!("branch 3");

                if c == "FUZZING" {
                    println!("branch 4");
                    panic!("branch 4 has been reached");
                }
            }
        }
    } else {
        println!("this is the default path");
    }
    println!("---------");
}
