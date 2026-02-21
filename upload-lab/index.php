<?php
// index.php - VULNERABLE UPLOAD CORE
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['upload'])) {
    $uploadDir = 'uploads/';
    // SECURITY MISTAKE: Directly using the client-provided filename
    $fileName = $_FILES['upload']['name'];
    $uploadPath = $uploadDir . $fileName;

    // No extension or magic byte validation performed
    if (move_uploaded_file($_FILES['upload']['tmp_name'], $uploadPath)) {
        echo "<h2>[+] File uploaded successfully!</h2>";
        echo "<p>Path: <a href='$uploadPath'>$uploadPath</a></p>";
    } else {
        echo "<h2>[-] Upload failed.</h2>";
    }
}
?>
<html>
<body>
    <h1>VibeCheck Lab: Vulnerable Upload</h1>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="upload">
        <input type="submit" value="Upload">
    </form>
</body>
</html>
