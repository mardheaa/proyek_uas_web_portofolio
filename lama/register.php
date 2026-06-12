<?php
include "koneksi.php";

if (isset($_POST['daftar'])) {

    $email = $_POST['email'];
    $password = $_POST['password'];

    // Cek domain email harus unsoqa.ac.id
    if (!str_ends_with($email, "@upitra.ac.id")) {
        echo "Email harus menggunakan domain upitra.ac.id";
        exit;
    }

    // Enkripsi password
    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    // Simpan ke database
    $query = "INSERT INTO tbl_users (email, password) 
              VALUES ('$email', '$password_hash')";

    if (mysqli_query($conn, $query)) {
        echo "Pendaftaran berhasil!";
    } else {
        echo "Gagal daftar: " . mysqli_error($conn);
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
</head>
<body>

<h2>Daftar Akun</h2>

<form method="POST">
    Email: <br>
    <input type="email" name="email" required><br><br>

    Password: <br>
    <input type="password" name="password" required><br><br>

    <button type="submit" name="daftar">Daftar</button>
</form>

</body>
</html>