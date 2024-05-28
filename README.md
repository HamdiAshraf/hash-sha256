Implement Hashing with Salts using SHA-256 Algorithm.

You should implement three functions:

generateSalt(length: number): string

(Generates a random string of given length)

hash(password: string, salt: string): string

(returns a combination of the salt and the hash)

compare(password: string, hashed: string): boolean

(BONUS: gets the salt from the hashed password, hashes the plain password and compares the results)
