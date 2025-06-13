use std::collections::HashSet;
use std::fs;
use std::io::{self, Write, BufRead, BufReader};
use std::path::Path;
use sha2::{Sha256, Digest};
use std::io::Read;
use chrono::Local;
use colored::*;



const ALLOWLIST_PATH: &str = "/home/<username>/Linux_AV/usr/Linux_Defender/allowlist.txt";
const ERRORLOG_PATH: &str = "/home/<username>/Linux_AV/usr/Linux_Defender/ErrorLog.txt";
const SCANLOG_PATH: &str = "/home/<username>/Linux_AV/usr/Linux_Defender/scanlog.txt";
const QUARANTINE_PATH: &str = "/home/<username>/Linux_AV/usr/Linux_Defender/Quarantine/";

fn errorlog(menu: &str, error_msg: &str) {
    let now = Local::now();
    let log_entry = format!(
        "[{}] [Menu: {}] [Error] {}\n",
        now.format("%Y-%m-%d %H:%M:%S"),
        menu,
        error_msg
    );
    if let Ok(mut file) = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(ERRORLOG_PATH)
    {
        let _ = file.write_all(log_entry.as_bytes());
    }
}

// Helper for reading lines from a file
fn read_lines<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    reader.lines().collect()
}

fn scan_log() {
    match read_lines(SCANLOG_PATH) {
        Ok(lines) => {
            let mut total_files = 0;
            let mut unreadable = 0;
            let mut threats = 0;
            let mut found_threats = Vec::new();
            for l in &lines {
                if l.contains("[THREAT FOUND") {
                    threats += 1;
                    if let Some(idx) = l.rfind(' ') {
                        found_threats.push(l[idx+1..].to_string());
                    }
                } else if l.contains("[Ok]") || l.contains("[Allowed]") || l.contains("[Blocked]") {
                    total_files += 1;
                } else if l.contains("unreadable") || l.contains("Could not read") {
                    unreadable += 1;
                }
            }
            println!("[Log] Last scan summary:");
            println!("Total files scanned: {}", total_files);
            println!("Unreadable files: {}", unreadable);
            println!("Total threats found: {}", threats);
            if !found_threats.is_empty() {
                println!("Threats found:");
                for (i, threat) in found_threats.iter().enumerate() {
                    println!("{}. {}", i+1, threat);
                }
            } else {
                println!("No threats found in last scan.");
            }
            println!("\nPress Enter to return to the main menu...");
            let mut dummy = String::new();
            let _ = io::stdin().read_line(&mut dummy);
        },
        Err(e) => {
            println!("[Log] No previous scan log found.");
            errorlog("Main Menu", &format!("Failed to read scan log: {}", e));
            println!("\nPress Enter to return to the main menu...");
            let mut dummy = String::new();
            let _ = io::stdin().read_line(&mut dummy);
        }
    }
}

fn load_signatures_set(path: &str) -> HashSet<String> {
    match read_lines(path) {
        Ok(lines) => lines.into_iter().map(|sig| sig.trim().to_string()).collect(),
        Err(e) => {
            errorlog("Signature Load", &format!("Failed to load signatures: {}", e));
            HashSet::new()
        }
    }
}

fn load_set(path: &str) -> HashSet<String> {
    match read_lines(path) {
        Ok(lines) => lines.into_iter().map(|l| l.trim().to_string()).collect(),
        Err(_) => HashSet::new(),
    }
}

fn file_hash(path: &Path) -> Option<String> {
    match fs::File::open(path) {
        Ok(mut file) => {
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 4096];
            loop {
                let n = match file.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        errorlog("File Hash", &format!("Failed to read file {}: {}", path.display(), e));
                        return None;
                    }
                };
                hasher.update(&buffer[..n]);
            }
            Some(format!("{:x}", hasher.finalize()))
        },
        Err(e) => {
            errorlog("File Hash", &format!("Failed to open file {}: {}", path.display(), e));
            None
        }
    }
}

fn log_scan_result(result: &str) {
    if let Err(e) = fs::OpenOptions::new().append(true).create(true).open(SCANLOG_PATH).and_then(|mut file| writeln!(file, "{}", result)) {
        errorlog("Scan Log", &format!("Failed to log scan result: {}", e));
    }
}

fn scan_file_optimized(
    path: &Path,
    signatures: &HashSet<String>,
    allowlist: &HashSet<String>,
    quarantine: &HashSet<String>,
    total: &mut usize,
    _unreadable: &mut usize,
    threats: &mut usize,
) {
    *total += 1;
    let path_str = path.to_string_lossy();
    if allowlist.contains(path_str.as_ref()) {
        println!("{} {}", "[Allowed]".green(), path.display());
        return;
    }
    if quarantine.contains(path_str.as_ref()) {
        println!("{} {}", "[Blocked]".yellow(), path.display());
        log_scan_result(&format!("[Blocked] {}", path.display()));
        return;
    }
    // Hash-based detection
    if let Some(hash) = file_hash(path) {
        if signatures.contains(&hash) {
            println!("{} {}", "[THREAT FOUND: HASH]".red(), path.display());
            log_scan_result(&format!("[THREAT FOUND: HASH] {}", path.display()));
            *threats += 1;
            return;
        }
    }
    // Keyword-based detection (case-insensitive, trims whitespace)
    if let Ok(mut file) = fs::File::open(path) {
        let mut content = String::new();
        if file.read_to_string(&mut content).is_ok() {
            let content_lower = content.to_lowercase();
            for sig in signatures {
                let sig_trimmed = sig.trim().to_lowercase();
                if sig_trimmed.len() > 0 && sig_trimmed.len() < 40 && !sig_trimmed.starts_with('#') {
                    if content_lower.contains(&sig_trimmed) {
                        println!("[Scanning] = {} {} {}", "[THREAT FOUND: KEYWORD".red(), format!("\"{}\"]", sig_trimmed).red(), path.display().to_string().red());
                        log_scan_result(&format!("[THREAT FOUND: KEYWORD \"{}\"] {}", sig_trimmed, path.display()));
                        *threats += 1;
                        return;
                    }
                }
            }
        }
    }
    println!("[Scanning] = {} {}", "[Ok]".green(), path.display());
}

fn custom_scan_optimized(
    path: &str,
    signatures: &HashSet<String>,
    allowlist: &HashSet<String>,
    quarantine: &HashSet<String>,
    total: &mut usize,
    unreadable: &mut usize,
    threats: &mut usize,
) {
    let p = Path::new(path.trim());
    if p.is_file() {
        scan_file_optimized(p, signatures, allowlist, quarantine, total, unreadable, threats);
    } else if p.is_dir() {
        if let Ok(entries) = fs::read_dir(p) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_file() {
                        scan_file_optimized(&path, signatures, allowlist, quarantine, total, unreadable, threats);
                    } else if path.is_dir() {
                        custom_scan_optimized(path.to_str().unwrap_or(""), signatures, allowlist, quarantine, total, unreadable, threats);
                    }
                }
            }
        } else {
            println!("{} {}", "[Unreadable]".truecolor(255,140,0), path); // orange
            *unreadable += 1;
            return;
        }
    } else {
        println!("{} Path not found or invalid.", "[Unreadable]".truecolor(255,140,0)); // orange
        *unreadable += 1;
    }
}

fn quick_scan_optimized(signatures: &HashSet<String>, allowlist: &HashSet<String>, quarantine: &HashSet<String>) {
    let _ = fs::write(SCANLOG_PATH, "");
    println!("[Quick Scan] Scanning /home and /tmp");
    let mut total = 0;
    let mut unreadable = 0;
    let mut threats = 0;
    custom_scan_optimized("/home", signatures, allowlist, quarantine, &mut total, &mut unreadable, &mut threats);
    custom_scan_optimized("/tmp", signatures, allowlist, quarantine, &mut total, &mut unreadable, &mut threats);
    println!("------------ Scan finished ------------");
    println!("Total files scanned: {}", total);
    println!("Unreadable files: {}", unreadable);
    println!("Total Threats found: {}", threats);
    println!("--------------------------------");
    let mut found_threats = HashSet::new();
    if let Ok(file) = fs::File::open(SCANLOG_PATH) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(l) = line {
                if l.contains("[THREAT FOUND") {
                    if let Some(idx) = l.rfind(' ') {
                        let path = l[idx+1..].to_string();
                        found_threats.insert(path);
                    }
                }
            }
        }
    }
    if !found_threats.is_empty() {
        println!("Show list of threats and take action? (y/n)");
        let mut yn = String::new();
        io::stdin().read_line(&mut yn).expect("Failed to read input");
        if yn.trim().to_lowercase() == "y" {
            println!("List of all Threats found in the last scan:");
            for (i, threat) in found_threats.iter().enumerate() {
                println!("{}. {}", i+1, threat);
            }
            println!("Enter the number of a threat to take action, or press Enter to return to the main menu:");
            let mut input = String::new();
            io::stdin().read_line(&mut input).expect("Failed to read input");
            if let Ok(choice) = input.trim().parse::<usize>() {
                if choice > 0 && choice <= found_threats.len() {
                    let threat_path = found_threats.iter().nth(choice-1).unwrap();
                    println!("Selected: {}", threat_path);
                    println!("Choose action: (A)llow, (B)lock, (S)kip, (M)ain menu");
                    let mut action = String::new();
                    io::stdin().read_line(&mut action).expect("Failed to read input");
                    match action.trim().to_lowercase().as_str() {
                        "a" => {
                            if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(ALLOWLIST_PATH) {
                                let _ = writeln!(file, "{}", threat_path);
                                println!("[Allow] {} is now allowed.", threat_path);
                            }
                        },
                        "b" => {
                            if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(QUARANTINE_PATH) {
                                let _ = writeln!(file, "{}", threat_path);
                                println!("[Quarantine] {} is now quarantined.", threat_path);
                            }
                        },
                        "m" => return,
                        _ => println!("No action taken."),
                    }
                }
            }
        }
    }
}

fn system_scan_optimized(signatures: &HashSet<String>, allowlist: &HashSet<String>, quarantine: &HashSet<String>) {
    let _ = fs::write(SCANLOG_PATH, "");
    println!("[System Scan] Scanning the entire filesystem (Warning: may take a long time!)");
    println!("------------ Scanning ------------");
    let mut total = 0;
    let mut unreadable = 0;
    let mut threats = 0;
    custom_scan_optimized("/", signatures, allowlist, quarantine, &mut total, &mut unreadable, &mut threats);
    println!("------------ Scan finished ------------");
    println!("Total files scanned: {}", total);
    println!("Unreadable files: {}", unreadable);
    println!("Total Threats found: {}", threats);
    println!("--------------------------------");
    let mut found_threats = HashSet::new();
    if let Ok(file) = fs::File::open(SCANLOG_PATH) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(l) = line {
                if l.contains("[THREAT FOUND") {
                    if let Some(idx) = l.rfind(' ') {
                        let path = l[idx+1..].to_string();
                        found_threats.insert(path);
                    }
                }
            }
        }
    }
    if !found_threats.is_empty() {
        println!("Show list of threats and take action? (y/n)");
        let mut yn = String::new();
        io::stdin().read_line(&mut yn).expect("Failed to read input");
        if yn.trim().to_lowercase() == "y" {
            println!("List of all Threats found in the last scan:");
            for (i, threat) in found_threats.iter().enumerate() {
                println!("{}. {}", i+1, threat);
            }
            println!("Enter the number of a threat to take action, or press Enter to return to the main menu:");
            let mut input = String::new();
            io::stdin().read_line(&mut input).expect("Failed to read input");
            if let Ok(choice) = input.trim().parse::<usize>() {
                if choice > 0 && choice <= found_threats.len() {
                    let threat_path = found_threats.iter().nth(choice-1).unwrap();
                    println!("Selected: {}", threat_path);
                    println!("Choose action: (A)llow, (B)lock, (S)kip, (M)ain menu");
                    let mut action = String::new();
                    io::stdin().read_line(&mut action).expect("Failed to read input");
                    match action.trim().to_lowercase().as_str() {
                        "a" => {
                            if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(ALLOWLIST_PATH) {
                                let _ = writeln!(file, "{}", threat_path);
                                println!("[Allow] {} is now allowed.", threat_path);
                            }
                        },
                        "b" => {
                            if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(QUARANTINE_PATH) {
                                let _ = writeln!(file, "{}", threat_path);
                                println!("[Quarantine] {} is now quarantined.", threat_path);
                            }
                        },
                        "m" => return,
                        _ => println!("No action taken."),
                    }
                }
            }
        }
    }
    println!("--------------------------------");
    println!("press Enter to return to the main menu:\n");
    let mut return_choice = String::new();
    io::stdin().read_line(&mut return_choice).expect("Failed to read input");
    println!("Returning to main menu...");
    println!("\n");

}

fn allow_file() {
    println!("[Allow] Enter the path of the file to allow:");
    let mut path = String::new();
    io::stdin().read_line(&mut path).expect("Failed to read input");
    let path = path.trim();
    if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(ALLOWLIST_PATH) {
        let _ = writeln!(file, "{}", path);
        println!("[Allow] {} is now allowed.", path);
    } else {
        println!("{}", "[Error] Could not open allowlist file.".white());
        errorlog("Allow File", "Could not open allowlist file for writing");
    }
}

fn quarantine_file() {
    println!("[Quarantine] Enter the path of the file to quarantine or press 'y' to choose a file from the threat list:\n");
    let mut path = String::new();
    io::stdin().read_line(&mut path).expect("[Error] Failed to read input!\n".white().to_string().as_str());
    let path = path.trim();
    let quarantine_dir = "/home/dog/Schreibtisch/Linux_AV/usr/Linux_Defender/Quarantine/";
    if Path::new(path).exists() {
        let file_name = Path::new(path).file_name().unwrap_or_default();
        if file_name == "" {
            println!("{}", "[Error] Invalid file name for quarantine!".white());
            errorlog("Quarantine File", &format!("Invalid file name: {}", path));
            return;
        }
        let quarantine_path = Path::new(quarantine_dir).join(file_name);
        // Benenne Datei um, falls sie nicht schon .quarantine-Endung hat
        let quarantine_path = if !quarantine_path.to_string_lossy().ends_with(".quarantine") {
            quarantine_path.with_extension(format!("{}quarantine", quarantine_path.extension().map(|e| e.to_string_lossy()).unwrap_or_default()))
        } else {
            quarantine_path
        };
        println!("[Quarantine] moving file into quarantine");
        if let Err(e) = fs::rename(path, &quarantine_path) {
            println!("{}", "[Error] Failed to move file into quarantine!".white());
            errorlog("Quarantine File", &format!("Failed to move file {}: {}", path, e));
            return;
        }
        // Setze Berechtigungen auf 000 (nicht lesbar, nicht schreibbar, nicht ausführbar)
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(&quarantine_path, fs::Permissions::from_mode(0o000)) {
            println!("{}", "[Error] Failed to set quarantine permissions!".white());
            errorlog("Quarantine File", &format!("Failed to set permissions for {}: {}", quarantine_path.display(), e));
        }
        if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(QUARANTINE_PATH) {
            let _ = writeln!(file, "{}", quarantine_path.display());
            println!("[Quarantine] {} has been moved to the quarantine list.", quarantine_path.display());
        } else {
            println!("[Error] Could not open quarantine file.");
            errorlog("Quarantine File", "Could not open quarantine file for writing");
        }

    } else if path.to_lowercase() == "y" {
        let mut found_threats = HashSet::new();
        if let Ok(file) = fs::File::open(SCANLOG_PATH) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(l) = line {
                    if l.contains("[THREAT FOUND") {
                        if let Some(idx) = l.rfind(' ') {
                            let threat_path = l[idx+1..].to_string();
                            found_threats.insert(threat_path);
                        }
                    }
                }
            }
        }



    } else {
        println!("[Error] The specified file does not exist, is invalid or unreadable!");
        errorlog("Quarantine File", &format!("File does not exist: {}", path));
    }
}

fn remove_file() {
    println!("[Remove] Enter the path of the file to remove or press 'y' to choose one from the threat list:\n");
    let mut path = String::new();
    io::stdin().read_line(&mut path).expect("[Error] Failed to read input!\n".white().to_string().as_str());
    let path = path.trim();
    if Path::new(&path).exists() {
        println!("[Remove] deleting file...");
        if let Err(e) = fs::remove_file(&path) {
            println!("[Error] Failed to delete the file!");
            errorlog("Remove File", &format!("Failed to delete file {}: {}", path, e));
        } else {
            println!("[Remove] {} deleted.", path);
        }

    } else if path.to_lowercase() == "y" {
        let mut found_threats = HashSet::new();
        if let Ok(file) = fs::File::open(SCANLOG_PATH) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(l) = line {
                    if l.contains("[THREAT FOUND") {
                        if let Some(idx) = l.rfind(' ') {
                            let threat_path = l[idx+1..].to_string();
                            found_threats.insert(threat_path);
                        }
                    }
                }
            }
        }
        let found_threats_vec: Vec<_> = found_threats.iter().cloned().collect();
        println!("Found threats:");
        for (i, threat) in found_threats_vec.iter().enumerate() {
            println!("{}. {}", i+1, threat);
        }
        println!("Enter the number of a threat to remove, or enter 'all' to remove all threats, or press Enter to return to the main menu:");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read input");
        let input = input.trim();
        if input == "all" {
            for threat in &found_threats_vec {
                if Path::new(threat).exists() {
                    if let Err(e) = fs::remove_file(threat) {
                        println!("[Error] Failed to delete the file: {}", threat);
                        errorlog("Remove File", &format!("Failed to delete file {}: {}", threat, e));
                    } else {
                        println!("[Remove] {} deleted.", threat);
                    }
                } else {
                    println!("[Error] The specified file does not exist: {}", threat);
                    errorlog("Remove File", &format!("File does not exist: {}", threat));
                }
            }
        } else if let Ok(index) = input.parse::<usize>() {
            if index > 0 && index <= found_threats_vec.len() {
                let threat = &found_threats_vec[index-1];
                if Path::new(threat).exists() {
                    if let Err(e) = fs::remove_file(threat) {
                        println!("[Error] Failed to delete the file: {}", threat);
                        errorlog("Remove File", &format!("Failed to delete file {}: {}", threat, e));
                    } else {
                        println!("[Remove] {} deleted.", threat);
                    }
                } else {
                    println!("[Error] The specified file does not exist: {}", threat);
                    errorlog("Remove File", &format!("File does not exist: {}", threat));
                }
            } else {
                println!("[Error] Invalid threat number.");
            }
        }

    } else {
        println!("[Error] The specified file does not exist, is invalid or unreadable!");
        errorlog("Remove File", &format!("File does not exist: {}", path));
    }
}




fn main() {
    // Optimiert: Signaturen, Allowlist und Quarantäne-Liste einmal laden
    let signatures = load_signatures_set("/home/<username>/Linux_AV/usr/Linux_Defender/signatures.txt");
    let allowlist = load_set(ALLOWLIST_PATH);
    let quarantine = load_set(QUARANTINE_PATH);
    loop {
        println!("\n");
        println!("{}", r#"
  _      _              _     _
 | |    (_)            \ \   / /         _    _         _
 | |     _              \ \_/ /         / \  \ \       / /
 | |    | |_ __  _   _   \   /         / _ \  \ \     / /
 | |    | | '_ \| | | |  / _ \        / /_\ \  \ \   / /
 | |____| | | | | |_| | / / \ \      / _____ \  \ \_/ /
 |______|_|_| |_|\__,_|/_/   \_\    /_/     \_\  \___/
                                              
             L I N U X   D E F E N D E R
"#.green());
        println!("Welcome to Linux Defender!");
        println!("---------------- Options ----------------");
        println!("1. Scan for Malware");
        println!("2. Show last scan log");
        println!("3. Allow/Quarantine/Remove a file");
        println!("4. Exit");
        println!("5. Information");
        println!("-----------------------------------------\n");
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed to read input");
        match choice.trim() {
            "1" => {
                println!("------- Scan Options -------");
                println!("1. System Scan");
                println!("2. Quick Scan");
                println!("3. Custom Scan");
                println!("4. Back to main menu");
                println!("---------------------------\n");
                let mut scan_choice = String::new();
                io::stdin().read_line(&mut scan_choice).expect("Failed to read input");
                match scan_choice.trim() {
                    "1" => {
                        println!("Initializing system scan...");
                        system_scan_optimized(&signatures, &allowlist, &quarantine);
                    },
                    "2" => {
                        println!("Initializing quick scan...");
                        quick_scan_optimized(&signatures, &allowlist, &quarantine);
                    },
                    "3" => {
                        println!("Configuring custom scan...");
                        println!("--------------------------");
                        println!("Enter the path to a file or directory to scan:");
                        let mut path3 = String::new();
                        io::stdin().read_line(&mut path3).expect("Failed to read input");
                        let _ = fs::write(SCANLOG_PATH, "");
                        let mut total = 0;
                        let mut unreadable = 0;
                        let mut threats = 0;
                        custom_scan_optimized(path3.trim(), &signatures, &allowlist, &quarantine, &mut total, &mut unreadable, &mut threats);
                        println!("------------ Scan finished ------------");
                        println!("Total files scanned: {}", total);
                        println!("Unreadable files: {}", unreadable);
                        println!("Threats found: {}", threats);
                        println!("--------------------------------");
                        use std::collections::HashSet;
                        let mut found_threats = HashSet::new();
                        if let Ok(file) = fs::File::open(SCANLOG_PATH) {
                            let reader = BufReader::new(file);
                            for line in reader.lines() {
                                if let Ok(l) = line {
                                    if l.contains("[THREAT FOUND") {
                                        if let Some(idx) = l.rfind(' ') {
                                            let path = l[idx+1..].to_string();
                                            found_threats.insert(path);
                                        }
                                    }
                                }
                            }
                        }
                        if !found_threats.is_empty() {
                            println!("Show list of threats and take action? (y/n)");
                            let mut yn = String::new();
                            io::stdin().read_line(&mut yn).expect("[Error] Failed to read input");
                            if yn.trim().to_lowercase() == "y" {
                                println!("List of all Threats found in the last scan:");
                                for (i, threat) in found_threats.iter().enumerate() {
                                    println!("{}. {}", i+1, threat);
                                }
                                println!("Enter the number of a threat to take action, or 'all' to take action on all or press Enter to return to the main menu:");
                                let mut input = String::new();
                                io::stdin().read_line(&mut input).expect("[Error] Failed to read input");
                                if let Ok(choice) = input.trim().parse::<usize>() {
                                    if choice > 0 && choice <= found_threats.len() {
                                        let threat_path = found_threats.iter().nth(choice-1).unwrap();
                                        println!("Selected: {}", threat_path);
                                        println!("Choose action: (A)llow, (B)lock, (S)kip, (M)ain menu");
                                        let mut action = String::new();
                                        io::stdin().read_line(&mut action).expect("[Error] Failed to read input");
                                        match action.trim().to_lowercase().as_str() {
                                            "a" => {
                                                if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(ALLOWLIST_PATH) {
                                                    let _ = writeln!(file, "{}", threat_path);
                                                    println!("[Allow] {} is now allowed.", threat_path);
                                                }
                                            },
                                            "b" => {
                                                if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(QUARANTINE_PATH) {
                                                    let _ = writeln!(file, "{}", threat_path);
                                                    println!("[Quarantine] {} is now quarantined.", threat_path);
                                                }
                                            },
                                            "m" => continue,
                                            _ => println!("No action taken."),
                                        }
                                    } else if input.trim().to_lowercase() == "all" {
                                        println!("What action do you want to take on all threats?");
                                        println!("(A)llow, (Q)uarantine, (R)emove, (M)ain menu");
                                        let mut action_all = String::new();
                                        io::stdin().read_line(&mut action_all).expect("[Error] Failed to read input");
                                        match action_all.trim().to_lowercase().as_str() {
                                            "a" => {
                                                if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(ALLOWLIST_PATH) {
                                                    for threat in &found_threats {
                                                        let _ = writeln!(file, "{}", threat);
                                                    }
                                                    println!("[Allow] All threats are now allowed.");
                                                }
                                            },
                                            "q" => {
                                                if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(QUARANTINE_PATH) {
                                                    for threat in &found_threats {
                                                        let _ = writeln!(file, "{}", threat);
                                                    }
                                                    println!("[Quarantine] All threats are now quarantined.");
                                                }
                                            },
                                            "r" => {
                                                for threat in &found_threats {
                                                    // Remove each threat file directly
                                                    if Path::new(threat).exists() {
                                                        if let Err(e) = fs::remove_file(threat) {
                                                            println!("[Error] Failed to delete the file: {}", threat);
                                                            errorlog("Remove File", &format!("Failed to delete file {}: {}", threat, e));
                                                        } else {
                                                            println!("[Remove] {} deleted.", threat);
                                                        }
                                                    } else {
                                                        println!("[Error] The specified file does not exist: {}", threat);
                                                        errorlog("Remove File", &format!("File does not exist: {}", threat));
                                                    }
                                                }
                                            },
                                            "m" => continue,
                                            _ => println!("No action taken."),
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "4" => continue,
                    _ => {
                        println!("Invalid scan option, please try again.");
                        continue;
                    }
                }
            },
            "2" => {
                println!("Showing last scan log...");
                scan_log();
            },
            "3" => {
                println!("------- Allow/Quarantine/Remove Options -------");
                println!("1. Allow a file");
                println!("2. Quarantine a file");
                println!("3. Remove a file");
                println!("4. Back to main menu");
                println!("-------------------------\n");
                let mut allow_block_choice = String::new();
                io::stdin().read_line(&mut allow_block_choice).expect("Failed to read input");
                match allow_block_choice.trim() {
                    "1" => allow_file(),
                    "2" => quarantine_file(),
                    "3" => remove_file(),
                    "4" => continue,
                    _ => {
                        println!("[Error] Invalid option, please try again.");
                        errorlog("Allow/Quarantine/Remove", "Invalid option selected");
                        continue;
                    }
                }
            },
            "4" => {
                println!("Exiting...");
                break;
            },
            "5" => {
                println!("--------- Information ---------");
                println!("Welcome to Linux Defender!");
                println!("This is a custom terminal-based anti-malware for Linux (Ubuntu-based systems).");
                println!("It is designed to detect and remove malware from your system.\n\
                Please keep in mind this is not a replacement for a full anti-malware solution,\n\
                but is designed to be a tool to help.\nWork in progress, please report any bugs or issues to my Github page.\n");
                println!("---------------------------------------------------------------");
                println!("Info about the project:\n");
                println!("dev team: I am the only developer of this project.");
                println!("version: 0.9.3");
                println!("Languages used: Rust");
                println!("---------------------------------------------------------------");
                println!("Thank you for using this tool!");
                println!("Press Enter to return to the main menu:");
                let mut return_choice = String::new();
                io::stdin().read_line(&mut return_choice).expect("Failed to read input");
            },
            _ => {
                println!("Invalid choice, please try again.");
            }
        }
    }
}
