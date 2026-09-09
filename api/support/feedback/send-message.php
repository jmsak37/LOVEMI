<?php
declare(strict_types=1);
require_once __DIR__ . '/common.php';

$pdo = sc_pdo();
sc_ensure_schema($pdo);
$admin = sc_admin_auth($pdo);
$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));

if ($method === 'GET') {
    $action = strtolower(sc_clean($_GET['action'] ?? '', 30));
    if ($action !== 'users') sc_response(false, 'Unsupported action.', ['code'=>'INVALID_ACTION'], 422);
    $search = sc_clean($_GET['search'] ?? '', 100);
    if (mb_strlen($search) < 2) sc_response(true, 'Enter at least 2 characters.', ['users'=>[]]);
    try {
        $like='%'.$search.'%';
        $stmt=$pdo->prepare("SELECT id,username,full_names,email FROM users WHERE is_deleted=0 AND is_suspended=0 AND is_active=1 AND (username LIKE :q1 OR full_names LIKE :q2 OR email LIKE :q3) ORDER BY full_names ASC,username ASC LIMIT 25");
        $stmt->execute([':q1'=>$like,':q2'=>$like,':q3'=>$like]);
        $users=$stmt->fetchAll(PDO::FETCH_ASSOC);
        sc_response(true,'Users loaded.',['users'=>array_map(static fn(array $u)=>['id'=>(int)$u['id'],'username'=>(string)($u['username']??''),'full_names'=>(string)($u['full_names']??''),'email'=>(string)($u['email']??'')],$users)]);
    } catch(Throwable $e){ error_log('[LOVEMI DIRECT USER SEARCH] '.$e->getMessage()); sc_response(false,'Unable to search LOVEMI users.',['code'=>'USER_SEARCH_FAILED'],500); }
}

if ($method !== 'POST') sc_response(false,'Only GET and POST requests are allowed.',['code'=>'METHOD_NOT_ALLOWED'],405);
$input=sc_input();
$userId=(int)($input['user_id']??0);
$email=trim((string)($input['email']??''));
$recipientName=sc_clean($input['recipient_name']??'',120);
$referenceId=sc_clean($input['reference_id']??'',120);
$subject=sc_clean($input['subject']??'',180);
$body=sc_clean($input['body']??'',20000);
$includeBranding=filter_var($input['include_branding']??true,FILTER_VALIDATE_BOOLEAN,FILTER_NULL_ON_FAILURE); $includeBranding=$includeBranding??true;
$includeReference=filter_var($input['include_reference']??true,FILTER_VALIDATE_BOOLEAN,FILTER_NULL_ON_FAILURE); $includeReference=$includeReference??true;

$user=null;
if($userId>0){
    $stmt=$pdo->prepare('SELECT id,username,full_names,email FROM users WHERE id=:id AND is_deleted=0 AND is_suspended=0 AND is_active=1 LIMIT 1');
    $stmt->execute([':id'=>$userId]); $user=$stmt->fetch(PDO::FETCH_ASSOC)?:null;
    if(!$user) sc_response(false,'The selected LOVEMI user was not found or is unavailable.',['code'=>'USER_NOT_FOUND'],404);
    $email=trim((string)$user['email']);
    if($recipientName==='') $recipientName=trim((string)($user['full_names']??$user['username']??'LOVEMI Member'));
    if($referenceId==='') $referenceId=(string)$userId;
}
if($email===''||!filter_var($email,FILTER_VALIDATE_EMAIL)||preg_match('/[\r\n]/',$email)) sc_response(false,'Enter a valid recipient email address.',['code'=>'INVALID_EMAIL'],422);
if($subject==='') sc_response(false,'Subject is required.',['code'=>'SUBJECT_REQUIRED'],422);
if(preg_match('/[\r\n]/',$subject)) sc_response(false,'Invalid subject.',['code'=>'INVALID_SUBJECT'],422);
if($body==='') sc_response(false,'Message body is required.',['code'=>'BODY_REQUIRED'],422);
if($recipientName==='') $recipientName='LOVEMI Member';

try{
    $pdo->beginTransaction();
    $token=bin2hex(random_bytes(48)); $hash=hash('sha256',$token);
    $category='other';
    $ticketStatus='awaiting_user';
    $ticketStmt=$pdo->prepare("INSERT INTO support_tickets(user_id,name,email,category,subject,message,status,source,last_admin_reply_at,last_message_at,close_at) VALUES(:uid,:name,:email,:category,:subject,:message,:status,'direct',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,DATE_ADD(CURRENT_TIMESTAMP,INTERVAL 48 HOUR))");
    $ticketStmt->execute([':uid'=>$userId>0?$userId:null,':name'=>$recipientName,':email'=>$email,':category'=>$category,':subject'=>$subject,':message'=>$body,':status'=>$ticketStatus]);
    $ticketId=(int)$pdo->lastInsertId();
    $msgStmt=$pdo->prepare("INSERT INTO support_ticket_messages(ticket_id,sender_type,sender_id,sender_name,sender_email,body) VALUES(:tid,'admin',:sid,:name,:email,:body)");
    $msgStmt->execute([':tid'=>$ticketId,':sid'=>(int)$admin['id'],':name'=>sc_clean($admin['full_names']??$admin['username']??'LOVEMI Support',180),':email'=>(string)($admin['email']??LOVEMI_SUPPORT_EMAIL),':body'=>$body]);
    $accessType='direct';
    $pdo->prepare('INSERT INTO support_ticket_access(ticket_id,access_type,token_hash) VALUES(:tid,:type,:hash)')->execute([':tid'=>$ticketId,':type'=>$accessType,':hash'=>$hash]);
    $pdo->commit();
} catch(Throwable $e){
    if($pdo->inTransaction()) $pdo->rollBack();
    error_log('[LOVEMI DIRECT TICKET CREATE] '.$e->getMessage());
    sc_response(false,'The LOVEMI message could not be saved as a support conversation.',['code'=>'TICKET_SAVE_FAILED'],500);
}

$ticketNo='LM-TKT-'.str_pad((string)$ticketId,6,'0',STR_PAD_LEFT);
$feedbackUrl=sc_feedback_url($token);
$logoUrl=sc_app_url().'/assets/logo1/logo1.png'; $footerLogo=sc_app_url().'/assets/logo1/apple-touch-icon.png';
$safeName=sc_html($recipientName); $safeSubject=sc_html($subject); $safeBody=nl2br(sc_html($body),false); $safeRef=sc_html($referenceId);
$brand=$includeBranding?'<div style="padding:28px;text-align:center;background:linear-gradient(135deg,#fbf8ff,#fff6fb);border-bottom:1px solid #eee7f5"><img src="'.sc_html($logoUrl).'" alt="LOVEMI" style="width:76px;height:76px;object-fit:contain;border-radius:18px;display:block;margin:0 auto 11px"><div style="font-family:Georgia,serif;font-size:31px;font-weight:800;color:#6d28d9">LOVEMI</div><div style="margin-top:5px;color:#8f8998;font-size:10px;letter-spacing:2px">DISCOVER • CONNECT • MEET</div></div>':'';
$refBlock=($includeReference&&$referenceId!=='')?'<div style="margin-top:20px;padding:12px 14px;border:1px solid #e9def7;border-radius:12px;background:#fbf8ff;color:#706979;font-size:12px"><strong style="color:#6d28d9">Reference / ID:</strong> '.$safeRef.'</div>':'';
$linkBlock='<div style="margin-top:25px;padding:18px;border-radius:15px;background:linear-gradient(135deg,#f7efff,#fff1f8);border:1px solid #eadcf7"><div style="font-weight:800;color:#5b21b6">Your secure reply link</div><p style="margin:7px 0 14px;font-size:13px;line-height:1.65;color:#5d5664">You can reply directly through the LOVEMI Support page without logging in or completing account verification for this message.</p><a href="'.sc_html($feedbackUrl).'" style="display:inline-block;padding:13px 21px;border-radius:11px;background:#6d28d9;color:#fff;text-decoration:none;font-weight:800">Open & Reply</a></div>';
$html='<!doctype html><html><body style="margin:0;padding:0;background:#f4f3f8;font-family:Arial,Helvetica,sans-serif;color:#1b1720"><div style="padding:34px 15px"><div style="max-width:700px;margin:0 auto;background:#fff;border:1px solid #e8e3ef;border-radius:22px;overflow:hidden;box-shadow:0 18px 55px rgba(52,29,85,.10)">'.$brand.'<div style="padding:30px"><div style="font-size:12px;font-weight:800;color:#6d28d9;text-transform:uppercase;letter-spacing:1.2px">LOVEMI Message</div><h1 style="margin:9px 0 0;font-family:Georgia,serif;font-size:27px;line-height:1.25">'.$safeSubject.'</h1><p style="margin:18px 0 0;font-size:15px;line-height:1.7;color:#534e59">Hello '.$safeName.',</p><div style="margin-top:15px;padding:19px 18px;border:1px solid #ece7f2;border-radius:15px;background:#fcfbfe;font-size:14px;line-height:1.85;color:#38333c">'.$safeBody.'</div>'.$refBlock.$linkBlock.'<div style="margin-top:24px;padding-top:18px;border-top:1px solid #eeeaf2;font-size:11px;line-height:1.7;color:#8b8591">This message was sent by an authorized LOVEMI administrator through the LOVEMI Support Center. Ticket '.$ticketNo.'.</div></div><div style="padding:18px 28px;background:#17131d;color:#b7b0be;text-align:center;font-size:10px;line-height:1.7">'.($includeBranding?'<img src="'.sc_html($footerLogo).'" alt="LOVEMI" style="width:26px;height:26px;object-fit:contain;vertical-align:middle;margin-right:6px;border-radius:7px">':'').'<span>LOVEMI • Discover • Connect • Meet</span></div></div></div></body></html>';
$text="LOVEMI

Hello {$recipientName},

{$subject}

{$body}

Ticket: {$ticketNo}
Reply securely: {$feedbackUrl}";
if($includeReference&&$referenceId!=='') $text.="
Reference / ID: {$referenceId}";
$sent=sc_mail($email,$recipientName,$subject,$html,$text);
if($userId>0) sc_notify_user($pdo,$userId,'New message from LOVEMI Support',$subject,$ticketId,(int)$admin['id']);
sc_response(true,$sent?'The LOVEMI email/message was sent and a replyable support conversation was created.':'The message was saved as a replyable support conversation, but the email could not be delivered.',[
    'email'=>$email,'user_id'=>$userId,'recipient_name'=>$recipientName,'subject'=>$subject,'ticket_id'=>$ticketId,'ticket_number'=>$ticketNo,'feedback_url'=>$feedbackUrl,'mail_sent'=>$sent,'access_type'=>'direct','branding'=>(bool)$includeBranding
]);
