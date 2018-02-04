"use strict";
var app = angular.module('AES-App', []);
app.controller('AES-Controller', ['$scope', function ($scope) {
    $scope.plaintext = "";
    $scope.ciphertext = "";
    $scope.key = "";
    $scope.mode = "CTR";
    $scope.counter = 0;
    $scope.iv = "";

    /**
     * @return {boolean}
     */
    $scope.IsCurrentKeyValid = function () {
        return $scope.key.length === 16 ||
            $scope.key.length === 24 ||
            $scope.key.length === 32;
    };
    /**
     * @return {boolean}
     */
    $scope.IsCurrentIVValid = function () {
        return $scope.iv.length === 16;
    };
    /**
     * @return {string}
     */
    $scope.GetCSSForFormValidity = function (isValid) {
        return isValid ? "has-success" : "has-error";
    };
    /**
     * @return {boolean}
     */
    $scope.DoesCurrentModeRequireCounter = function () {
        return $scope.mode === "CTR";
    };
    /**
     * @return {boolean}
     */
    $scope.DoesCurrentModeRequireIV = function () {
        return $scope.mode === "CBC" ||
            $scope.mode === "CFB" ||
            $scope.mode === "OFB" ||
            $scope.mode === "ECB";
    };
    /**
     * @return {boolean}
     */
    $scope.IsReady = function () {
        return $scope.IsCurrentKeyValid() && (!$scope.DoesCurrentModeRequireIV() || $scope.IsCurrentIVValid());
    };
    /**
     * @return {object}
     */
    $scope.ConstructCipher = function () {
        switch ($scope.mode) {
            case "CTR":
                return new aesjs.ModeOfOperation.ctr(aesjs.utils.utf8.toBytes($scope.key), new aesjs.Counter($scope.counter));
            case "CBC":
                return new aesjs.ModeOfOperation.cbc(aesjs.utils.utf8.toBytes($scope.key), aesjs.utils.utf8.toBytes($scope.iv));
            case "CFB":
                return new aesjs.ModeOfOperation.cfb(aesjs.utils.utf8.toBytes($scope.key), aesjs.utils.utf8.toBytes($scope.iv));
            case "OFB":
                return new aesjs.ModeOfOperation.ofb(aesjs.utils.utf8.toBytes($scope.key), aesjs.utils.utf8.toBytes($scope.iv));
            case "ECB":
                return new aesjs.ModeOfOperation.ecb(aesjs.utils.utf8.toBytes($scope.key), aesjs.utils.utf8.toBytes($scope.iv));
            default:
                return null;
        }
    };
    $scope.Encrypt = function () {
        if (!$scope.IsReady())
            return;

        // Convert text to bytes
        var textBytes = aesjs.utils.utf8.toBytes($scope.plaintext);

        var aes = $scope.ConstructCipher();
        if (aes === null) {
            return;
        }
        var encryptedBytes = aes.encrypt(textBytes);

        // To print or store the binary data, you may convert it to hex
        $scope.ciphertext = aesjs.utils.hex.fromBytes(encryptedBytes);
    };
    $scope.Decrypt = function () {
        if (!$scope.IsReady())
            return;

        // When ready to decrypt the hex string, convert it back to bytes
        var encryptedBytes = aesjs.utils.hex.toBytes($scope.ciphertext);

        var aes = $scope.ConstructCipher();
        if (aes === null) {
            return;
        }
        var decryptedBytes = aes.decrypt(encryptedBytes);

        // Convert our bytes back into text
        $scope.plaintext = aesjs.utils.utf8.fromBytes(decryptedBytes);
    };
}]);
