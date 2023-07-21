use common::{cli_util};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};
use interface::{UserSubmissionBlobUpdated}

#[cfg_attr(feature = "trusted", serde(crate = "serde_sgx"))]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct UserSubmissionMessagePackageUpdated {
    pub ciphertext: UserSubmissionBlobUpdated,
    pub agg_url: std::string::String,
};

pub(crate) fn load_msgpackage(save_path: &str) -> Result<UserSubmissionMessagePackageUpdated> {
    let save_file = File::open(save_path)?;
    Ok(cli_util::load(save_file)?)
}

pub(crate) fn save_msgpackage(save_path: impl AsRef<Path>, msgpackage: &UserSubmissionMessagePackageUpdated) -> Result<()> {
    let save_file = File::create(save_path)?;
    Ok(cli_util::save(save_file, state)?)
}

// impl UserSubmissionMessagePackageUpdated{
//     pub fn save_data_to_file(data: &UserSubmissionMessagePackageUpdated, filename: &str) -> std::io::Result<()> {
//         let file = File::create(filename)?;
//         serde_json::to_writer(file, data)?;
//         Ok(())
//     }
    
//     // 从文件中读取data_to_save
//     pub fn load_data_from_file(filename: &str) -> std::io::Result<UserSubmissionMessagePackageUpdated> {
//         let file = File::open(filename)?;
//         let reader = std::io::BufReader::new(file);
//         let data: UserSubmissionMessagePackageUpdated = serde_json::from_reader(reader)?;
//         Ok(data)
//     }
// }

// #[cfg(test)]
// mod tests{
//     #[test]
//     fn test_haha() -> Result<(EntityId)>{
//         let a = UserSubmissionBlobUpdated.default();
//         let b = "https://example.com";
//         let c = UserSubmissionMessagePackageUpdated{a,b};
//         save_data_to_file(&c, "data.json").expect("Failed to save data to file.");
//         let loaded_data = load_data_from_file("data.json").expect("Failed to load data from file.");
//         println!("Loaded data: {:?}", loaded_data);
//     }
    
// }