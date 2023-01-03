<?php

declare(strict_types=1);

use Conia\Crypt\Crypt;

test('Encryption and decryption', function () {
    $encrypted = Crypt::encrypt('Symbolic', 'secret-key');
    $decrypted = Crypt::decrypt($encrypted, 'secret-key');

    expect($encrypted)->not->toBe('Symbolic');
    expect($decrypted)->not->toBe($encrypted);
    expect($decrypted)->toBe('Symbolic');
});


test('Encryption and decryption with alternate algo', function () {
    $encrypted = Crypt::encrypt('Symbolic', 'secret-key', 'aes-256-cbc');
    $decrypted = Crypt::decrypt($encrypted, 'secret-key', 'aes-256-cbc');

    expect($encrypted)->not->toBe('Symbolic');
    expect($decrypted)->not->toBe($encrypted);
    expect($decrypted)->toBe('Symbolic');
});


test('Failing encryption', function () {
    Crypt::encrypt('Symbolic', 'secret-key', 'wrong-algo');
})->throws(ValueError::class, 'Cipher algorithm');


test('Failing decryption', function () {
    Crypt::decrypt('Symbolic', 'secret-key', 'wrong-algo');
})->throws(ValueError::class, 'Cipher algorithm');
