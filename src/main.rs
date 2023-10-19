use anyhow::Result;
use clap::Parser;
use sdbtree::storage::dir::DirectoryStorage;
use sdbtreefs::SDBTreeFs;
use std::fs;

#[derive(Parser)]
struct Args {
    /// The path of the filesystem's mount
    #[clap(short, long, default_value = "/tmp/sdbtreefsmnt")]
    mount: String,

    /// The directory to pass VFS calls through to
    #[clap(short, long, default_value = "/tmp/sdbtreefsdata")]
    datadir: String,

    /// The directory to store Lethe's metadata in
    #[clap(short = 't', long, default_value = "/tmp/sdbtreefsmeta")]
    metadir: String,

    /// The enclave to store Lethe's master key in
    #[clap(short, long, default_value = "/tmp/sdbtreefsenclave")]
    enclave: String,

    /// The degree to use for the BTree
    #[clap(short = 'n', long, default_value_t = 2)]
    degree: usize,

    /// Run filesystem in debug mode
    #[clap(short = 'v', long, default_value_t = false)]
    debug: bool,

    /// Run filesystem in foreground
    #[clap(short, long, default_value_t = false)]
    foreground: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let _ = fs::create_dir_all(&args.mount);
    let _ = fs::create_dir_all(&args.datadir);
    let _ = fs::create_dir_all(&args.metadir);

    pretty_env_logger::init();

    SDBTreeFs::options()
        .debug(args.debug)
        .foreground(args.foreground)
        .degree(args.degree)
        .build(
            &args.enclave,
            &args.datadir,
            &args.metadir,
            DirectoryStorage::new(&args.metadir)?,
        )?
        .mount(args.mount)
}
