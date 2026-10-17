use std::io::{self, BufRead};

fn main() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY, 0, 0, 0);
    }

    let mut health: i32 = 100;
    let mut mana: f32 = 50.0;
    let player_name = "HeroPlayer\0";

    let pid = std::process::id();
    println!("=== DUMMY GAME STARTED ===");
    println!("PID: {pid}");
    println!("Health address: 0x{:X} (value: {health})", &health as *const i32 as usize);
    println!("Mana address:   0x{:X} (value: {mana})", &mana as *const f32 as usize);
    println!("Name address:   0x{:X} (value: {player_name})", player_name.as_ptr() as usize);
    println!("\nCommands: 'hit' (hp - 10), 'heal' (hp + 20), 'val' (print), 'exit'");

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let cmd = line.trim();
        match cmd {
            "hit" => {
                health -= 10;
                mana -= 5.0;
                println!("Took damage! Health = {health}, Mana = {mana}");
            }
            "heal" => {
                health += 20;
                println!("Healed! Health = {health}, Mana = {mana}");
            }
            "val" => {
                println!("Current: Health = {health}, Mana = {mana}");
            }
            "exit" => break,
            _ => println!("Unknown command. Try 'hit', 'heal', 'val', 'exit'"),
        }
    }
}
