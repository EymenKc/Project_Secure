import base64


def file_to_base64(file_path):
    with open(file_path, "rb") as file:
        # Encode the binary data in Base64
        base64_data = base64.b64encode(file.read())
        # Convert bytes to a string
        base64_string = base64_data.decode('utf-8')

        return base64_string

            
def base64_to_file(file_name, decrypted_data, format, folder_name="Decrypted_files"):

    # Create a file and write binary data to it
    with open(f"{folder_name}/{file_name}.{format}", "wb") as decoded_file:
        decoded_file.write(decrypted_data)

