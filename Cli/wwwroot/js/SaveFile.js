function FileSaveAs(filename, encoding, fileContent) {
    var link = document.createElement('a');
    link.download = filename;
    link.href = encoding + encodeURIComponent(fileContent)
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}