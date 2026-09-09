<?php
declare(strict_types=1);
require_once __DIR__ . '/common.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') sc_response(false,'Only POST requests are allowed.',['code'=>'METHOD_NOT_ALLOWED'],405);
$pdo=sc_pdo(); sc_ensure_schema($pdo); $admin=sc_admin_auth($pdo); $in=sc_input(); $id=(int)($in['ticket_id']??0);
if($id<=0) sc_response(false,'Invalid ticket.',['code'=>'INVALID_TICKET'],422);
$ticket=sc_get_ticket($pdo,$id); if(!$ticket) sc_response(false,'Ticket not found.',['code'=>'TICKET_NOT_FOUND'],404);
if(trim((string)$ticket['email'])==='') sc_response(false,'This ticket has no email address.',['code'=>'NO_EMAIL'],422);

try{
    $token=bin2hex(random_bytes(48));
    $hash=hash('sha256',$token);
    $access=$pdo->prepare('SELECT id,access_type FROM support_ticket_access WHERE ticket_id=:id LIMIT 1');
    $access->execute([':id'=>$id]); $row=$access->fetch(PDO::FETCH_ASSOC);
    if($row){
        $pdo->prepare('UPDATE support_ticket_access SET token_hash=:h,updated_at=CURRENT_TIMESTAMP WHERE ticket_id=:id LIMIT 1')->execute([':h'=>$hash,':id'=>$id]);
    }else{
        $pdo->prepare('INSERT INTO support_ticket_access(ticket_id,access_type,token_hash) VALUES(:id,:type,:h)')->execute([':id'=>$id,':type'=>((int)($ticket['user_id']??0)>0?'account':'guest'),':h'=>$hash]);
    }
    $url=sc_feedback_url($token);
    $name=sc_clean($ticket['name']??'LOVEMI Member',120);
    $number='LM-TKT-'.str_pad((string)$id,6,'0',STR_PAD_LEFT);
    $subject='LOVEMI Support secure conversation - '.$number;
    $html='<div style="font-family:Arial,sans-serif;background:#f6f3fa;padding:28px"><div style="max-width:680px;margin:auto;background:#fff;border-radius:20px;overflow:hidden;border:1px solid #e9e1f1"><div style="padding:26px;text-align:center;background:linear-gradient(135deg,#fbf8ff,#fff5fb)"><img src="'.sc_html(sc_app_url().'/assets/logo1/logo1.png').'" alt="LOVEMI" style="width:68px;height:68px;object-fit:contain;border-radius:16px"><h2 style="margin:10px 0 0;color:#6d28d9">LOVEMI Support</h2><div style="font-size:10px;letter-spacing:2px;color:#8f8998;margin-top:4px">DISCOVER • CONNECT • MEET</div></div><div style="padding:28px"><p>Hello '.sc_html($name).',</p><p>Your secure support conversation is ready.</p><div style="padding:16px;background:#fbf9fd;border:1px solid #eee7f5;border-radius:12px"><strong>Ticket:</strong> '.sc_html($number).'<br><strong>Subject:</strong> '.sc_html((string)$ticket['subject']).'</div><p style="margin-top:20px"><a href="'.sc_html($url).'" style="display:inline-block;padding:13px 20px;border-radius:11px;background:#6d28d9;color:#fff;text-decoration:none;font-weight:800">Open & Reply to Support</a></p><p style="font-size:12px;color:#777">This secure link opens the LOVEMI Support-Ticket-Feedback page. Keep it private.</p></div></div></div>';
    $mail=sc_mail((string)$ticket['email'],$name,$subject,$html,"Open and reply to your LOVEMI support conversation: {$url}");
} catch(Throwable $e){ error_log('[LOVEMI SEND LINK] '.$e->getMessage()); sc_response(false,'The secure support link could not be generated.',['code'=>'LINK_FAILED'],500); }
sc_response(true,$mail?'Secure support link sent to the requester.':'Secure link generated, but the email could not be delivered.',['mail_sent'=>$mail,'feedback_url'=>$url,'ticket_id'=>$id]);
