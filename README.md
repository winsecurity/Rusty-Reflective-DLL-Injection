# Rusty-Reflective-DLL-Injection

This tool is just my practice on pe loading. I write bad code and do not use it directly without modification.

## Compilation
- First compile the injector, This will inject the dll into the target process and runs the myloader() function. use `cargo build --release` to compile the injector. (Change the path to dll or download from a url)
- Now `cd reflection`
- Next modify the code inside DllMain() of reflection dll and compile it using `cargo build --release`

## Credits 

https://github.com/stephenfewer/ReflectiveDLLInjection

