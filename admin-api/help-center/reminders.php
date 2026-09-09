<?php
declare(strict_types=1); require_once __DIR__ . '/common.php';
$pdo=sc_pdo();sc_ensure_schema($pdo);
$isCli=(PHP_SAPI==='cli');
if(!$isCli){ sc_admin_auth($pdo); }
$now=time();$sent=[];
// Auto-close only conversations waiting on the user, never tickets waiting for support.
$close=$pdo->query("UPDATE support_tickets SET status='closed',solved_at=COALESCE(solved_at,CURRENT_TIMESTAMP),closed_at=CURRENT_TIMESTAMP,close_at=NULL WHERE status IN ('awaiting_user','solved') AND close_at IS NOT NULL AND close_at <= CURRENT_TIMESTAMP");
// User reminders: approximately 24h/12h/1h before close.
$windows=[['24',86400,'reminder_24_sent'],['12',43200,'reminder_12_sent'],['1',3600,'reminder_1_sent']];
foreach($windows as [$label,$seconds,$flag]){
    $stmt=$pdo->prepare("SELECT id,user_id,name,email,subject,close_at,source FROM support_tickets WHERE status IN ('awaiting_user','solved') AND close_at IS NOT NULL AND close_at > CURRENT_TIMESTAMP AND close_at <= DATE_ADD(CURRENT_TIMESTAMP, INTERVAL {$seconds} SECOND) AND {$flag}=0 ORDER BY id ASC LIMIT 100");
    $stmt->execute();$rows=$stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach($rows as $t){
        $claim=$pdo->prepare("UPDATE support_tickets SET {$flag}=1 WHERE id=:id AND {$flag}=0 LIMIT 1");$claim->execute([':id'=>(int)$t['id']]);if($claim->rowCount()!==1)continue;
        $token=bin2hex(random_bytes(48));
        $claimToken=$pdo->prepare('UPDATE support_ticket_access SET token_hash=:h,updated_at=CURRENT_TIMESTAMP WHERE ticket_id=:id LIMIT 1');
        $claimToken->execute([':h'=>hash('sha256',$token),':id'=>(int)$t['id']]);
        $url=sc_app_url().'/Support-Ticket-Feedback.html?token='.rawurlencode($token);
        $html='<div style="font-family:Arial,sans-serif;max-width:650px;margin:auto;padding:24px;background:#f7f7fb"><div style="background:#fff;border-radius:18px;padding:28px"><h2 style="color:#6d28d9">LOVEMI Support reminder</h2><p>Hello '.sc_html((string)$t['name']).',</p><p>Your support conversation <strong>LM-TKT-'.str_pad((string)$t['id'],6,'0',STR_PAD_LEFT).'</strong> is still waiting for your response.</p><p>It is scheduled to close in approximately <strong>'.$label.' hour(s)</strong> unless you reply or reopen it.</p><p>Please use your secure ticket link from the previous LOVEMI Support email to continue the conversation.</p></div></div>';
        $mail=sc_mail((string)$t['email'],(string)$t['name'],'LOVEMI Support reminder - '.$label.' hour(s) remaining',$html);
        if((int)($t['user_id']??0)>0)sc_notify_user($pdo,(int)$t['user_id'],'Support ticket reminder','Your LOVEMI support ticket will close in about '.$label.' hour(s) unless you reply.',(int)$t['id']);
        $sent[]=['ticket_id'=>(int)$t['id'],'type'=>$label,'mail_sent'=>$mail];
    }
}
// Admin reminders for tickets waiting for support; these do NOT get closed automatically.
$stmt=$pdo->query("SELECT id,subject,name FROM support_tickets WHERE status='awaiting_admin' ORDER BY COALESCE(last_message_at,created_at) ASC LIMIT 100");
$waiting=$stmt?$stmt->fetchAll(PDO::FETCH_ASSOC):[];
foreach($waiting as $t){
    $id=(int)$t['id'];$check=$pdo->prepare("SELECT admin_last_reminder_at FROM support_tickets WHERE id=:id LIMIT 1");$check->execute([':id'=>$id]);$last=$check->fetchColumn();$due=(!$last || (time()-strtotime((string)$last))>=3600);if(!$due)continue;
    $pdo->prepare("UPDATE support_tickets SET admin_last_reminder_at=CURRENT_TIMESTAMP WHERE id=:id LIMIT 1")->execute([':id'=>$id]);
    sc_notify_admins($pdo,'Support reply needed','Ticket LM-TKT-'.str_pad((string)$id,6,'0',STR_PAD_LEFT).' is waiting for a support reply.', $id);
}
if($isCli){echo json_encode(['success'=>true,'closed'=>(int)$close->rowCount(),'reminders'=>$sent],JSON_UNESCAPED_SLASHES).PHP_EOL;exit;}
sc_response(true,'Support reminders processed.',['closed'=>(int)$close->rowCount(),'reminders'=>$sent]);
