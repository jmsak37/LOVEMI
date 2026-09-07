<?php
declare(strict_types=1);
require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../config/profile-code.php';
ini_set('display_errors','0');ini_set('display_startup_errors','0');
header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');header('Pragma: no-cache');header('Expires: 0');
function publicProfileCodeResponse(bool $success,string $message,array $data=[],int $status=200):never{http_response_code($status);echo json_encode(array_merge(['success'=>$success,'message'=>$message],$data),JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);exit;}
if(($_SERVER['REQUEST_METHOD']??'')!=='GET')publicProfileCodeResponse(false,'Only GET requests are allowed.',['code'=>'METHOD_NOT_ALLOWED'],405);
$targetUserId=(int)($_GET['user_id']??0);if($targetUserId<=0)publicProfileCodeResponse(false,'A valid user_id is required.',['code'=>'INVALID_USER_ID'],422);
try{$pdo=db();}catch(Throwable $e){error_log('[LOVEMI PUBLIC PROFILE CODE DB] '.$e->getMessage());publicProfileCodeResponse(false,'Unable to connect to the database.',['code'=>'DATABASE_ERROR'],500);}
try{
$stmt=$pdo->prepare("SELECT u.id,u.account_status,u.email_verified,u.is_active,u.is_suspended,u.is_deleted,r.is_admin_role,p.profile_visibility FROM users u LEFT JOIN roles r ON r.id=u.role_id LEFT JOIN profiles p ON p.user_id=u.id WHERE u.id=:user_id LIMIT 1");$stmt->execute([':user_id'=>$targetUserId]);$user=$stmt->fetch(PDO::FETCH_ASSOC);
if(!$user)publicProfileCodeResponse(false,'The requested profile could not be found.',['code'=>'USER_NOT_FOUND'],404);
if((int)$user['is_admin_role']===1)publicProfileCodeResponse(false,'This profile is not available.',['code'=>'PROFILE_UNAVAILABLE'],403);
if((int)$user['is_active']!==1||(int)$user['is_suspended']===1||(int)$user['is_deleted']===1||(int)$user['email_verified']!==1||strtolower((string)$user['account_status'])!=='approved')publicProfileCodeResponse(false,'This profile is not currently available.',['code'=>'PROFILE_UNAVAILABLE'],403);
if(strtolower(trim((string)($user['profile_visibility']??'public'))) !== 'public')publicProfileCodeResponse(false,'This profile is not currently public.',['code'=>'PROFILE_NOT_PUBLIC'],403);
$checkTable=$pdo->query("SHOW TABLES LIKE 'profile_codes'");if(!$checkTable||!$checkTable->fetch()){$pdo->exec("CREATE TABLE IF NOT EXISTS profile_codes (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,user_id BIGINT UNSIGNED NOT NULL,code_hash CHAR(64) NOT NULL,encrypted_payload TEXT NOT NULL,version SMALLINT UNSIGNED NOT NULL DEFAULT 1,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,PRIMARY KEY(id),UNIQUE KEY uq_profile_codes_user_id(user_id),UNIQUE KEY uq_profile_codes_hash(code_hash)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");}
$profileCode='';$codeHash='';for($attempt=0;$attempt<10;$attempt++){ $candidate=lovemiBase64UrlEncode(random_bytes(24));$candidateHash=hash('sha256',$candidate);$check=$pdo->prepare('SELECT id FROM profile_codes WHERE code_hash=:code_hash LIMIT 1');$check->execute([':code_hash'=>$candidateHash]);if(!$check->fetchColumn()){$profileCode=$candidate;$codeHash=$candidateHash;break;} }
if($profileCode===''||$codeHash==='')throw new RuntimeException('Unable to allocate a unique profile code.');
$payload=['user_id'=>$targetUserId,'code'=>$profileCode,'version'=>LOVEMI_PROFILE_CODE_VERSION,'created_at'=>time(),'nonce'=>bin2hex(random_bytes(16))];$encryptedPayload=lovemiEncryptProfilePayload($payload);
$pdo->beginTransaction();$delete=$pdo->prepare('DELETE FROM profile_codes WHERE user_id=:user_id');$delete->execute([':user_id'=>$targetUserId]);$insert=$pdo->prepare('INSERT INTO profile_codes(user_id,code_hash,encrypted_payload,version,created_at,updated_at) VALUES(:user_id,:code_hash,:encrypted_payload,:version,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)');$insert->execute([':user_id'=>$targetUserId,':code_hash'=>$codeHash,':encrypted_payload'=>$encryptedPayload,':version'=>LOVEMI_PROFILE_CODE_VERSION]);$pdo->commit();
publicProfileCodeResponse(true,'Secure public profile code created successfully.',['profile_code'=>$profileCode,'version'=>LOVEMI_PROFILE_CODE_VERSION]);
}catch(Throwable $e){if(isset($pdo)&&$pdo instanceof PDO&&$pdo->inTransaction())$pdo->rollBack();error_log('[LOVEMI PUBLIC PROFILE CODE] '.$e->getMessage());publicProfileCodeResponse(false,'Unable to create the secure profile code.',['code'=>'PROFILE_CODE_CREATE_ERROR'],500);}
