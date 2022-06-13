use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use generic_array::typenum::U16;
use std::{
    env::args,
    fs::{self, File},
    process,
};

fn main() {
    //just argparsing stuff nothing crazy
    let mut args = args();

    args.next();

    let mode = match args.next() {
        Some(mode) if mode == "e" => 0,
        Some(mode) if mode == "d" => 1,
        _ => {
            eprintln!("expected mode 'e'- encrypt or 'd' decrypt");
            process::exit(0);
        }
    };

    let file = match args.next() {
        Some(file) => match File::open(&file) {
            Ok(_) => file,
            Err(e) => {
                eprintln!("failed to open file {}", e);
                process::exit(0);
            }
        },
        _ => {
            eprintln!("expected file path");
            process::exit(0);
        }
    };

    let key_stem = match args.next() {
        Some(stem) => stem,
        _ => {
            eprintln!("expected key for encryption/decryption");
            process::exit(0);
        }
    };

    //reading stuff in and calling the pre-encryption functions on it
    let data = fs::read(&file).unwrap();
    let key = gen_key(key_stem.as_bytes());
    let blocks = process_data(&data);
    let cipher = Aes128::new(&key);

    //takes the processed blocks encrypts them individually and then concatenates them into an encrypted Vec<u8>
    let new_content = blocks.into_iter().fold(vec![], |mut new_content, block| {
        let mut block = GenericArray::from(block);

        if mode == 0 {
            cipher.encrypt_block(&mut block);
        } else {
            cipher.decrypt_block(&mut block);
        }

        new_content.append(&mut Vec::from(&*block));

        new_content
            .into_iter()
            .filter(|&byte| byte != 0u8)
            .collect::<Vec<u8>>()
    });

    println!("{:?}", String::from_utf8_lossy(&new_content));

    fs::write(&file, &new_content).unwrap();
}

//takes in sub key in the form of a u8 array and converts it into a usable key of size 16
fn gen_key(sub_key: &[u8]) -> GenericArray<u8, U16> {
    let mut sub_key = Vec::from(sub_key);

    //put the key onto the end of itself if it is shorter than 16
    while sub_key.len() < 16 {
        sub_key.append(&mut sub_key.clone())
    }

    //take the first 16 of the sub key and return it in a generic array
    let key: [u8; 16] = sub_key
        .into_iter()
        .take(16)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    GenericArray::from(key)
}

//takes data in the form of u8 array and chunks it into equal 16 byte u8 arrays
fn process_data(data: &[u8]) -> Vec<[u8; 16]> {
    //determining which product of 16 the length of the buffer needs to be
    let buffer_len = 16 * (data.len() as f64 / 16f64).round() as usize;

    //adds the number of necessary 0s to the end of data to reach buffer length
    let mut data_in_buffer = Vec::from(data);

    data_in_buffer.append(&mut vec![0; buffer_len - data.len()]);

    let mut data_in_buffer = data_in_buffer.into_iter();

    //chunks up the data_in_buffer into 16 byte slices and returns that as one vector
    (0..(buffer_len / 16))
        .map(|_| {
            (&mut data_in_buffer)
                .take(16)
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<[u8; 16]>>()
}
