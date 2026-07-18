const cloudinary = require('cloudinary').v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

// Sobe um buffer de arquivo pro Cloudinary
// Retorna { url, public_id }
async function uploadBuffer(buffer, originalName, folder = 'documentos') {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder,
        resource_type: 'auto', // detecta imagem, pdf, etc
        public_id: `${Date.now()}-${Math.random().toString(36).slice(2,8)}`,
        overwrite: true
      },
      (err, result) => {
        if (err) return reject(err);
        resolve({ url: result.secure_url, public_id: result.public_id });
      }
    );
    stream.end(buffer);
  });
}

async function deleteFile(publicId) {
  if (!publicId) return;
  try {
    await cloudinary.uploader.destroy(publicId);
  } catch (e) {
    console.error('Erro ao deletar do Cloudinary:', e.message);
  }
}

module.exports = { cloudinary, uploadBuffer, deleteFile };
