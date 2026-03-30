<?php
// SMTP mailer utility
require_once 'config.php';
require_once 'app_settings.php';

class SMTPMailer {
    private $db;
    private $settingsManager;

    public function __construct($db) {
        $this->db = $db;
        $this->settingsManager = new AppSettingsManager($db);
    }

    public function isConfigured() {
        $settings = $this->settingsManager->getSmtpSettings();

        if (!$settings['enabled']) {
            return false;
        }

        return !empty($settings['host']) && !empty($settings['port']) && !empty($settings['from_email']);
    }

    public function send($toEmail, $subject, $htmlBody = '', $textBody = '') {
        $settings = $this->settingsManager->getSmtpSettings();

        if (!$settings['enabled']) {
            return ['success' => false, 'error' => 'SMTP is disabled.'];
        }

        if (empty($settings['host']) || empty($settings['port']) || empty($settings['from_email'])) {
            return ['success' => false, 'error' => 'SMTP settings are incomplete.'];
        }

        if (!filter_var($toEmail, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'error' => 'Invalid recipient email address.'];
        }

        $subject = trim($subject);
        if ($subject === '') {
            return ['success' => false, 'error' => 'Email subject is required.'];
        }

        $textBody = trim($textBody);
        $htmlBody = trim($htmlBody);
        if ($textBody === '' && $htmlBody === '') {
            return ['success' => false, 'error' => 'Email body is required.'];
        }

        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false
            ]
        ]);

        $host = $settings['host'];
        $port = intval($settings['port']);
        $encryption = in_array($settings['encryption'], ['none', 'tls', 'ssl'], true) ? $settings['encryption'] : 'tls';

        $remoteHost = $host;
        if ($encryption === 'ssl') {
            $remoteHost = 'ssl://' . $host;
        }

        $socket = @stream_socket_client(
            $remoteHost . ':' . $port,
            $errno,
            $errstr,
            30,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$socket) {
            return ['success' => false, 'error' => 'Failed to connect to SMTP server: ' . $errstr];
        }

        stream_set_timeout($socket, 30);

        try {
            $this->expectCode($socket, [220]);
            $this->writeLine($socket, 'EHLO ' . getHost());
            $this->expectCode($socket, [250]);

            if ($encryption === 'tls') {
                $this->writeLine($socket, 'STARTTLS');
                $this->expectCode($socket, [220]);

                if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    throw new Exception('Failed to start TLS encryption.');
                }

                $this->writeLine($socket, 'EHLO ' . getHost());
                $this->expectCode($socket, [250]);
            }

            if ($settings['auth_required']) {
                if (empty($settings['username']) || empty($settings['password'])) {
                    throw new Exception('SMTP authentication is enabled but username/password is missing.');
                }

                $this->writeLine($socket, 'AUTH LOGIN');
                $this->expectCode($socket, [334]);

                $this->writeLine($socket, base64_encode($settings['username']));
                $this->expectCode($socket, [334]);

                $this->writeLine($socket, base64_encode($settings['password']));
                $this->expectCode($socket, [235]);
            }

            $this->writeLine($socket, 'MAIL FROM:<' . $settings['from_email'] . '>');
            $this->expectCode($socket, [250]);

            $this->writeLine($socket, 'RCPT TO:<' . $toEmail . '>');
            $this->expectCode($socket, [250, 251]);

            $this->writeLine($socket, 'DATA');
            $this->expectCode($socket, [354]);

            $rawMessage = $this->buildRawMessage(
                $settings['from_name'],
                $settings['from_email'],
                $toEmail,
                $subject,
                $htmlBody,
                $textBody
            );

            fwrite($socket, $rawMessage . "\r\n.\r\n");
            $this->expectCode($socket, [250]);

            $this->writeLine($socket, 'QUIT');
            fclose($socket);

            return ['success' => true];
        } catch (Exception $e) {
            if (is_resource($socket)) {
                fclose($socket);
            }
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    private function buildRawMessage($fromName, $fromEmail, $toEmail, $subject, $htmlBody, $textBody) {
        $encodedSubject = function_exists('mb_encode_mimeheader')
            ? mb_encode_mimeheader($subject, 'UTF-8')
            : $subject;

        $safeFromName = trim($fromName) !== '' ? str_replace(["\r", "\n"], '', $fromName) : SITE_NAME;
        $safeFromEmail = str_replace(["\r", "\n"], '', $fromEmail);
        $safeToEmail = str_replace(["\r", "\n"], '', $toEmail);

        $headers = [];
        $headers[] = 'From: ' . $safeFromName . ' <' . $safeFromEmail . '>';
        $headers[] = 'To: <' . $safeToEmail . '>';
        $headers[] = 'Subject: ' . $encodedSubject;
        $headers[] = 'Date: ' . date(DATE_RFC2822);
        $headers[] = 'MIME-Version: 1.0';

        if ($htmlBody !== '') {
            $boundary = 'boundary_' . bin2hex(random_bytes(12));
            $headers[] = 'Content-Type: multipart/alternative; boundary="' . $boundary . '"';

            $plainPart = $textBody !== '' ? $textBody : strip_tags($htmlBody);

            $body = '--' . $boundary . "\r\n";
            $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
            $body .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
            $body .= $plainPart . "\r\n\r\n";

            $body .= '--' . $boundary . "\r\n";
            $body .= "Content-Type: text/html; charset=UTF-8\r\n";
            $body .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
            $body .= $htmlBody . "\r\n\r\n";
            $body .= '--' . $boundary . '--';
        } else {
            $headers[] = 'Content-Type: text/plain; charset=UTF-8';
            $headers[] = 'Content-Transfer-Encoding: 8bit';
            $body = $textBody;
        }

        return implode("\r\n", $headers) . "\r\n\r\n" . $body;
    }

    private function writeLine($socket, $line) {
        fwrite($socket, $line . "\r\n");
    }

    private function expectCode($socket, $validCodes) {
        $line = '';
        $response = '';

        do {
            $line = fgets($socket, 1024);
            if ($line === false) {
                throw new Exception('Unexpected end of SMTP response.');
            }
            $response .= $line;
        } while (isset($line[3]) && $line[3] === '-');

        $code = intval(substr($line, 0, 3));
        if (!in_array($code, $validCodes, true)) {
            throw new Exception('SMTP error: ' . trim($response));
        }

        return $response;
    }
}
?>