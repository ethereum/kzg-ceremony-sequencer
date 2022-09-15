static CONTRIBUTION_SCHEMA: Lazy<Mutex<Schema>> = Lazy::new(|| {
    // Load schema
    let schema =
serde_json::from_str(include_str!("../../specs/contributionSchema.json")).
unwrap();     let schema = valico::schema::compile(schema).unwrap();
    schema
});
