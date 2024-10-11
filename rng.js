const fs = require('fs');
const crypto = require('crypto');

/**
 * A secure HMAC-based deterministic RNG.
 * This function initializes with a seed and generates random bytes deterministically.
 */
class HmacDrbg {
  constructor(seed) {
    this.seed = seed;
    this.counter = 0;
  }

  generateRandomBytes(size) {
    const randomBytes = Buffer.alloc(size);

    for (let i = 0; i < size; i += 32) { // 32 bytes = 256 bits
      // Create a new HMAC for each chunk, ensuring we don't reuse finalized HMACs
      const hmac = crypto.createHmac('sha256', this.seed);

      const data = Buffer.concat([Buffer.from(this.counter.toString()), this.seed]);
      const chunk = hmac.update(data).digest();
      chunk.copy(randomBytes, i, 0, Math.min(32, size - i)); // Fill the randomBytes buffer

      this.counter++;
    }

    return randomBytes;
  }
}

// Function to securely gather seed material
const generateSecureSeed = () => {
  // Combine multiple entropy sources, e.g., secure random data and timestamp
  const secureRandom = crypto.randomBytes(64); // 512 bits from crypto
  const timeEntropy = Buffer.from(Date.now().toString()); // System clock timestamp as additional entropy
  return Buffer.concat([secureRandom, timeEntropy]); // Combine entropy sources
};

// Function to generate random bits and write to file
const generateRandomBits = async () => {
  const totalBits = 100000000; // 100 million bits
  const totalBytes = Math.ceil(totalBits / 8);

  const writeStream = fs.createWriteStream('secureRandomBits.bin');
  const chunkSize = 1024 * 1024; // 1 MB chunks
  let bytesWritten = 0;

  // Secure seeding
  const seed = generateSecureSeed();
  console.log('Generated secure seed:', seed.toString('hex'));

  // Instantiate the HMAC-DRBG with the seed
  const rng = new HmacDrbg(seed);

  // Write random data in chunks
  while (bytesWritten < totalBytes) {
    const bytesToWrite = Math.min(chunkSize, totalBytes - bytesWritten);
    const randomData = rng.generateRandomBytes(bytesToWrite);
    writeStream.write(randomData);
    bytesWritten += bytesToWrite;
  }

  writeStream.end();
  writeStream.on('finish', () => {
    console.log('Random bitstream generation complete.');
  });
};

generateRandomBits();