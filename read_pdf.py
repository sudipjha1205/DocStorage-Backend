import PyPDF2
import pytesseract
from PIL import Image

def read_pdf(file_path):
    """Read a PDF file and return the text content."""

    pdf_file = open(file_path, "rb")
    pdf_reader = PyPDF2.PdfReader(pdf_file)
    num_pages = len(pdf_reader.pages)
    text = ""
    for i in range(num_pages):
        # Replace getPage with pages[]
        page = pdf_reader.pages[i]
        text += page.extract_text()
    pdf_file.close()
    return text

def read_image(file_path):
    """Read an image file and return the text content."""

    image = Image.open(file_path)
    text = pytesseract.image_to_string(image)
    return text

def main():
    """Read a PDF file and print the text content."""

    file_path = "/home/sudip/Downloads/KYC.pdf"
    text = read_pdf(file_path)
    print(text)

if __name__ == "__main__":
    main()

