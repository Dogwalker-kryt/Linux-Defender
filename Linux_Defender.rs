use chrono;
use std::fs;
use std::io::{self, Write, BufRead, BufReader};
use std::path::Path;
use sha2::{Sha256, Digest};
use std::io::Read;

fn thread_list() {
    println!("What Threats do you want to see?");
    println!("--------- Threats ---------");
    println!("1. Blocked Threats");
    println!("2. Allowed Threats");
    println!("3. Back to the main menu");
    println!("---------------------------\n");
    let mut list_choice = String::new();
    io::stdin().read_line(&mut list_choice).expect("Failed to read input");
    if list_choice == "1" {
        println!("[Blocked Threats]");
        if let Ok(file) = fs::File::open("blocklist.txt") {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(l) = line {
                    println!("{}", l);
                }
            }
        } else {
            println!("No blocked threats found.");
        }
    } else if list_choice == "2" {
        println!("[Allowed Threats]");
        if let Ok(file) = fs::File::open("allowlist.txt") {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(l) = line {
                    println!("{}", l);
                }
            }
        } else {
            println!("No allowed threats found.");
        }
    } else if list_choice == "3" {
        return; // Go back to the main menu
    } else {
        println!("Invalid choice, please try again.");
    }
}

fn block_threat() {
    println!("[Block] Enter the path of the file to block:");
    let mut file = fs::OpenOptions::new().append(true).create(true).open("blocklist.txt").unwrap();
    let mut path = String::new();
    io::stdin().read_line(&mut path).expect("Failed to read input");
    writeln!(file, "{}", path.trim()).unwrap();
    println!("{} has been added to the blocklist.", path.trim());
}

fn allow_threath() {
    println!("[Allow] Enter the path of the file to allow:");
    let mut file = fs::OpenOptions::new().append(true).create(true).open("allowlist.txt").unwrap();
    let mut path = String::new();
    io::stdin().read_line(&mut path).expect("Failed to read input");
    writeln!(file, "{}", path.trim()).unwrap();
    println!("{} is now allowed.", path.trim());
}

fn scan_log() {
    // Print the last scan log from scanlog.txt if it exists
    if let Ok(file) = fs::File::open("scanlog.txt") {
        println!("[Log] Last scan:\n");
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(l) = line {
                println!("{}", l);
            }
        }
    } else {
        println!("[Log] No previous scan log found.");
    }
}

fn load_signatures() -> Vec<String> {
    let mut sigs = Vec::new();
    if let Ok(file) = fs::File::open("AV_Software/signatures.txt") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(sig) = line {
                sigs.push(sig.trim().to_string());
            }
        }
    }
    sigs
}

fn file_hash(path: &Path) -> Option<String> {
    if let Ok(mut file) = fs::File::open(path) {
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 4096];
        loop {
            let n = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => return None,
            };
            hasher.update(&buffer[..n]);
        }
        Some(format!("{:x}", hasher.finalize()))
    } else {
        None
    }
}

fn is_allowed(path: &Path) -> bool {
    if let Ok(file) = fs::File::open("allowlist.txt") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(allowed) = line {
                if path.to_string_lossy() == allowed.trim() {
                    return true;
                }
            }
        }
    }
    false
}

fn is_blocked(path: &Path) -> bool {
    if let Ok(file) = fs::File::open("blocklist.txt") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(blocked) = line {
                if path.to_string_lossy() == blocked.trim() {
                    return true;
                }
            }
        }
    }
    false
}

fn log_scan_result(result: &str) {
    let mut file = fs::OpenOptions::new().append(true).create(true).open("scanlog.txt").unwrap();
    writeln!(file, "{}", result).unwrap();
}

fn scan_file(path: &Path, signatures: &Vec<String>, total: &mut usize, unreadable: &mut usize) {
    *total += 1;
    if is_allowed(path) {
        println!("[Allowed] {}", path.display());
        return;
    }
    if is_blocked(path) {
        println!("[Blocked] {}", path.display());
        log_scan_result(&format!("[Blocked] {}", path.display()));
        return;
    }
    if let Some(hash) = file_hash(path) {
        if signatures.contains(&hash) {
            println!("[THREAT FOUND] {}", path.display());
            log_scan_result(&format!("[THREAT FOUND] {}", path.display()));
        } else {
            println!("[OK] {}", path.display());
        }
    } else {
        println!("[Unreadable] {}", path.display());
        *unreadable += 1;
    }
}

fn custom_scan(path: &str, total: &mut usize, unreadable: &mut usize) {
    let signatures = load_signatures();
    println!("[Custom Scan] Scanning: {}", path);
    let p = Path::new(path.trim());
    if p.is_file() {
        scan_file(p, &signatures, total, unreadable);
    } else if p.is_dir() {
        for entry in fs::read_dir(p).unwrap_or_else(|_| fs::ReadDir::from(vec![])) {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() {
                    scan_file(&path, &signatures, total, unreadable);
                } else if path.is_dir() {
                    custom_scan(path.to_str().unwrap_or(""), total, unreadable);
                }
            }
        }
    } else {
        println!("Path not found or invalid.");
        *unreadable += 1;
    }
}

fn quick_scan() {
    println!("[Quick Scan] Scanning /home and /tmp");
    custom_scan("/home");
    custom_scan("/tmp");
}

fn system_scan() {
    println!("[System Scan] Scanning the entire filesystem (Warning: may take a long time!)");
    println!("------------ Scanning ------------");
    let mut total = 0;
    let mut unreadable = 0;
    custom_scan("/", &mut total, &mut unreadable);
    println!("------------ Scan finished ------------");
    println!("Total files scanned: {}", total);
    println!("Unreadable files: {}", unreadable);
}

fn setup_on_first_run() {
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    // Get home directory
    let home = env::var("HOME").unwrap_or("/tmp".to_string());
    let desktop = PathBuf::from(&home).join("Desktop");
    let defender_dir = desktop.join("LinuxDefender");

    // Create main folder
    if !defender_dir.exists() {
        println!("[Setup] First run detected. Creating LinuxDefender folder and copying files to Desktop...");
        fs::create_dir_all(&defender_dir).ok();

        // Copy self (the executable)
        if let Ok(current_exe) = env::current_exe() {
            let exe_name = current_exe.file_name().unwrap_or_default();
            let target_exe = defender_dir.join(exe_name);
            let _ = fs::copy(&current_exe, &target_exe);
            let _ = fs::set_permissions(&target_exe, fs::Permissions::from_mode(0o755));
        }

        // Create empty allowlist, blocklist, scanlog
        let _ = fs::File::create(defender_dir.join("allowlist.txt"));
        let _ = fs::File::create(defender_dir.join("blocklist.txt"));
        let _ = fs::File::create(defender_dir.join("scanlog.txt"));

        // Create a default signatures.txt with a sample hash
        let default_sigs = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 # Example: SHA256 of empty file\n";
        let _ = fs::write(defender_dir.join("signatures.txt"), default_sigs);

        // Optionally: create a README
        let _ = fs::write(defender_dir.join("README.txt"),
            "LinuxDefender - Your simple terminal antivirus.\nRun the executable in this folder to start scanning.\n");
    }
}

fn main() {
    setup_on_first_run();
    println!("Hello!");
    println!("Welcome to a custom terminal based Anti-Malware for Linux!");
    println!("Options:");
    println!("-------------------------");
    println!("1. Scan for Malware");
    println!("2. Show last scan log");
    println!("3. Allow/Block a file");
    println!("4. Exit");
    println!("5. Information");
    println!("-------------------------\n");
    let mut choice = String::new();
    io::stdin().read_line(&mut choice).expect("Failed to read input");
    if choice == "1" {
        println!("------- Scan Options -------");
        println!("1. System Scan");
        println!("2. Quick Scan");
        println!("3. Custom Scan");
        println!("4. Back to main menu");
        println!("---------------------------\n");
        let mut scan_choice = String::new();
        io::stdin().read_line(&mut scan_choice).expect("Failed to read input");
        if scan_choice == "1" {
            // Here you would implement the system scan logic
            println!("Initializing system scan...");
            system_scan();
            
        } else if scan_choice == "2" {
            // Here is the quick scan logic
            prinln!("Initializing quick scan...");
            quick_scan();
            
        } else if scan_choice == "3" {
            // Here is the custom scan logic
            println!("Configuring custom scan...");
            println!("--------------------------");
            println!("Enter the Path to a file or dircetory to scan:\n");
            let mut path3 = String::new();
            io::stdin().read_line(&mut path3).expect("Failed to read input");
            println!("Scanning {}...", path3);
            custom_scan();
            
        } else if scan_choice == "4" {
            println!("Returning to main menu...");
            return main();
        } else {
            println!("Invalid choice, please try again.");
            return main();
        }
    } else if choice == "2" {
        println!("Showing last scan log...");
        // Here is the logic to show the last scan log
        scan_log();
    } else if choice == "3" {
        println!("Allow/Block a file");
        // Here is the logic to allow/block a file
        println!("------- Allow/Block Options -------");
        println!("1. Allow a file");
        println!("2. Block a file");
        println!("3. Back to main menu");
        println!("-------------------------\n");
        let mut allow_block_choice = String::new();
        io::stdin().read_line(&mut allow_block_choice).expect("Failed to read input");
        if allow_block_choice == "1" {
            println!("Enter the file path to allow:");
            let mut file_path = String::new();
            io::stdin().read_line(&mut file_path).expect("Failed to read input");
            println!("File {} has been allowed.", file_path.trim());
            // Here you would implement the logic to allow the file
        } else if allow_block_choice == "2" {
            println!("Enter the file path to block:");
            let mut file_path = String::new();
            io::stdin().read_line(&mut file_path).expect("Failed to read input");
            println!("File {} has been blocked.", file_path.trim());
            // Here you would implement the logic to block the file
        } else allow_block_choice == "3" {
            println!("Returning to main menu...");
            return main();
        }
    } else if choice == "4" {
        println!("Exiting...");
        return;
    } else if choice == "5" {
        println!("Info:");
        prinln!("This is a custom Terminal based Anti-Malware for Linux (Ubuntu based systems).");
        prinln!("It is designed to dectect and remove malware from your system.\n"
        "Please ceap in mind this is not a replacement for a full Anti-Malware solution\n"
        "but its designed to be a tool to do that.\n"
        "Work in progress, please report any bugs or issues to my Github page.\n");
        println!("---------------------------------------------------------------");
        println!("Info about the project:\n"
        "dev team: Iam the only developer of this project.\n"
        "version: 0.1.0\n"
        "Langauges used: Rust, Bash, \n"
        "")
        println!("---------------------------------------------------------------");
        println!("Thank you for using this tool!");
        println!("press any key to return to the main menu:\n");
        let mut return_choice = String::new();
        io::stdin().read_line(&mut return_choice).expect("Failed to read input");
        return main();
     
    } else {
        println!("Invalid choice, please try again.");
        return main();
    }

}