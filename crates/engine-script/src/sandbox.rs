use crate::error::ScriptResult;
use mlua::{Lua, Nil, Value};

/// Initialize Lua 5.4 runtime with security sandboxing enabled.
/// Removes dangerous operating system, file I/O, and code loading primitives.
pub fn create_sandboxed_lua() -> ScriptResult<Lua> {
    let lua = Lua::new();

    {
        let globals = lua.globals();

        // Strip dangerous global libraries
        globals.set("os", Nil)?;
        globals.set("io", Nil)?;
        globals.set("package", Nil)?;
        globals.set("debug", Nil)?;

        // Strip dangerous global loader functions
        globals.set("dofile", Nil)?;
        globals.set("loadfile", Nil)?;
        globals.set("require", Nil)?;
    }

    Ok(lua)
}

/// Helper to verify if the sandboxed Lua environment blocks unsafe access
pub fn verify_sandbox(lua: &Lua) -> bool {
    let globals = lua.globals();
    let has_os = globals.get::<_, Value>("os").map_or(false, |v| !v.is_nil());
    let has_io = globals.get::<_, Value>("io").map_or(false, |v| !v.is_nil());
    !has_os && !has_io
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_blocks_os_and_io() {
        let lua = create_sandboxed_lua().expect("Failed to create sandboxed Lua");
        assert!(verify_sandbox(&lua));

        // Test running safe code
        let result: i32 = lua
            .load("return 2 + 2")
            .eval()
            .expect("Safe math must work");
        assert_eq!(result, 4);

        // Test that os is nil
        let os_type: String = lua
            .load("return type(os)")
            .eval()
            .expect("Type check must work");
        assert_eq!(os_type, "nil");

        // Test that io is nil
        let io_type: String = lua
            .load("return type(io)")
            .eval()
            .expect("Type check must work");
        assert_eq!(io_type, "nil");
    }
}

