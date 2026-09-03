fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    auditable_build::collect_dependency_list();
}
