from PIL import Image

DELIMITER = "#####"

def to_bin(data):
    """Convierte texto o números a binario de 8 bits."""
    if isinstance(data, str):
        return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, bytes):
        return ''.join([format(i, "08b") for i in data])
    elif isinstance(data, int):
        return format(data, "08b")
    else:
        raise TypeError("Tipo de dato no soportado.")

def encode(image_path, secret_message, output_path):
    """Oculta un mensaje dentro de una imagen."""
    print(f"[*] Ocultando mensaje en {image_path}...")
    
  
    image = Image.open(image_path, 'r')
    new_image = image.copy()
    
    full_message = secret_message + DELIMITER
    binary_message = to_bin(full_message)
    data_len = len(binary_message)
    
    width, height = new_image.size
    pixels = new_image.load()
    
    data_index = 0
    
    for y in range(height):
        for x in range(width):
            if data_index >= data_len:
                break
            
            pixel = list(pixels[x, y])
            
            for i in range(3):
                if data_index < data_len:
                    pixel[i] = pixel[i] & ~1 | int(binary_message[data_index])
                    data_index += 1

            pixels[x, y] = tuple(pixel)
        
        if data_index >= data_len:
            break
            
    new_image.save(output_path)
    print(f"[OK] Imagen guardada en: {output_path}")

def decode(image_path):
    """Extrae un mensaje oculto de una imagen."""
    print(f"[*] Leyendo imagen {image_path}...")
    
    image = Image.open(image_path, 'r')
    pixels = image.load()
    width, height = image.size
    
    binary_data = ""
    
    for y in range(height):
        for x in range(width):
            pixel = list(pixels[x, y])
            
            for i in range(3):
                binary_data += str(pixel[i] & 1)

    all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
    
    decoded_message = ""
    for byte in all_bytes:
        try:
            decoded_message += chr(int(byte, 2))
            
            if decoded_message[-5:] == DELIMITER:
                return decoded_message[:-5]
        except:
            break
            
    return "No se encontró ningún mensaje oculto."
