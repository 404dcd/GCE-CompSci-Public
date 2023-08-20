emcc emscript.c lib/libtomcrypt.a lib/libtommath.a -o static/emscript.js \
    -sEXPORT_ES6=1 -sMODULARIZE -sEXPORT_NAME="createMyModule" -sALLOW_MEMORY_GROWTH=1 \
    -sEXPORTED_RUNTIME_METHODS=cwrap,writeAsciiToMemory \
    -sEXPORTED_FUNCTIONS=_malloc,_free