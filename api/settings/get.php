<?php
declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

function settingsGetResponse(bool $success,string $message,array $data=[],int $status=200): never {
    http_response_code($status);
    echo json_encode(array_merge(['success'=>$success,'message'=>$message],$data),JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    settingsGetResponse(false,'Only GET requests are allowed.', ['code'=>'METHOD_NOT_ALLOWED'],405);
}

$userId=(int)($_SESSION['lovemi_user_id'] ?? 0);
if($userId<=0){
    settingsGetResponse(false,'Please log in first.',['code'=>'AUTHENTICATION_REQUIRED','redirect'=>'login.html'],401);
}

try{$pdo=db();}catch(Throwable $e){
    error_log('[LOVEMI SETTINGS GET DB] '.$e->getMessage());
    settingsGetResponse(false,'Unable to connect to the database.',['code'=>'DATABASE_ERROR'],500);
}

try{
    $stmt=$pdo->prepare("SELECT id,username,email,email_verified,two_factor_enabled,is_active,is_suspended,is_deleted,account_status FROM users WHERE id=:user_id LIMIT 1");
    $stmt->execute([':user_id'=>$userId]);
    $user=$stmt->fetch(PDO::FETCH_ASSOC);
}catch(Throwable $e){
    error_log('[LOVEMI SETTINGS USER] '.$e->getMessage());
    settingsGetResponse(false,'Unable to load your account.',['code'=>'USER_LOOKUP_FAILED'],500);
}

if(!$user) settingsGetResponse(false,'Your account could not be found.',['code'=>'USER_NOT_FOUND'],404);
if((int)$user['is_deleted']===1) settingsGetResponse(false,'Your account is no longer available.',['code'=>'ACCOUNT_DELETED'],403);
if((int)$user['is_suspended']===1) settingsGetResponse(false,'Your account is suspended.',['code'=>'ACCOUNT_SUSPENDED'],403);
if((int)$user['is_active']!==1) settingsGetResponse(false,'Your account is inactive.',['code'=>'ACCOUNT_INACTIVE'],403);

$defaults=[
    'email_notifications'=>1,'sms_notifications'=>1,'push_notifications'=>1,
    'connection_notifications'=>1,'message_notifications'=>1,'premium_notifications'=>1,
    'system_notifications'=>1,'sound_enabled'=>1
];

try{
    $stmt=$pdo->prepare("SELECT email_notifications,sms_notifications,push_notifications,connection_notifications,message_notifications,premium_notifications,system_notifications,sound_enabled,updated_at FROM notification_preferences WHERE user_id=:user_id LIMIT 1");
    $stmt->execute([':user_id'=>$userId]);
    $row=$stmt->fetch(PDO::FETCH_ASSOC);
    if(!$row){
        $ins=$pdo->prepare("INSERT INTO notification_preferences(user_id) VALUES(:user_id) ON DUPLICATE KEY UPDATE user_id=user_id");
        $ins->execute([':user_id'=>$userId]);
        $row=$defaults;
    }
}catch(Throwable $e){
    $row=$defaults;
}

$notifications=[
    'email_notifications'=>(int)($row['email_notifications']??1),
    'sms_notifications'=>(int)($row['sms_notifications']??1),
    'push_notifications'=>(int)($row['push_notifications']??1),
    'connection_notifications'=>(int)($row['connection_notifications']??1),
    'message_notifications'=>(int)($row['message_notifications']??1),
    'premium_notifications'=>(int)($row['premium_notifications']??1),
    'system_notifications'=>(int)($row['system_notifications']??1),
    'sound_enabled'=>(int)($row['sound_enabled']??1),
    'updated_at'=>$row['updated_at']??null
];

$contentSecurity=['default_allow_repost'=>1,'default_allow_video_download'=>1];
try{
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS user_content_security (
            user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
            default_allow_repost TINYINT(1) NOT NULL DEFAULT 1,
            default_allow_video_download TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");
    $stmt=$pdo->prepare("SELECT default_allow_repost,default_allow_video_download,created_at,updated_at FROM user_content_security WHERE user_id=:user_id LIMIT 1");
    $stmt->execute([':user_id'=>$userId]);
    $security=$stmt->fetch(PDO::FETCH_ASSOC);
    if(!$security){
        $ins=$pdo->prepare("INSERT INTO user_content_security(user_id) VALUES(:user_id) ON DUPLICATE KEY UPDATE user_id=user_id");
        $ins->execute([':user_id'=>$userId]);
    }else{
        $contentSecurity=[
            'default_allow_repost'=>(int)$security['default_allow_repost'],
            'default_allow_video_download'=>(int)$security['default_allow_video_download'],
            'created_at'=>$security['created_at'],
            'updated_at'=>$security['updated_at']
        ];
    }
}catch(Throwable $e){
    error_log('[LOVEMI SETTINGS CONTENT SECURITY] '.$e->getMessage());
}

$locationEnabled=true;
try{
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS user_location_preferences (
            user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
            live_location_enabled TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");
    $ins=$pdo->prepare("INSERT INTO user_location_preferences(user_id) VALUES(:user_id) ON DUPLICATE KEY UPDATE user_id=user_id");
    $ins->execute([':user_id'=>$userId]);
    $stmt=$pdo->prepare("SELECT live_location_enabled,updated_at FROM user_location_preferences WHERE user_id=:user_id LIMIT 1");
    $stmt->execute([':user_id'=>$userId]);
    $pref=$stmt->fetch(PDO::FETCH_ASSOC);
    if($pref)$locationEnabled=(int)$pref['live_location_enabled']===1;
}catch(Throwable $e){
    error_log('[LOVEMI SETTINGS LOCATION] '.$e->getMessage());
}

settingsGetResponse(true,'Settings loaded successfully.',[
    'account'=>[
        'id'=>$userId,
        'username'=>(string)$user['username'],
        'email'=>(string)$user['email'],
        'email_verified'=>(bool)$user['email_verified'],
        'two_factor_enabled'=>(bool)$user['two_factor_enabled'],
        'account_status'=>(string)$user['account_status']
    ],
    'notifications'=>$notifications,
    'content_security'=>$contentSecurity,
    'location'=>[
        'live_location_enabled'=>$locationEnabled?1:0
    ],
    'settings'=>[
        'notifications'=>$notifications,
        'content_security'=>$contentSecurity,
        'location'=>['live_location_enabled'=>$locationEnabled?1:0]
    ]
]);
