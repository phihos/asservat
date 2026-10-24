# native85 — worker read complete; hub projection consume >=3 s then unavailable

Worker: three unwraps, decrypt, parse, frames all fast; stopped awaiting the
hub acknowledgement. Hub q-projection >=3 s, refused before acknowledging.
