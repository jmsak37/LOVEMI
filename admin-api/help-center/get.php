<?php
declare(strict_types=1); require_once __DIR__ . '/common.php';
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') sc_response(false,'Only GET requests are allowed.',['code'=>'METHOD_NOT_ALLOWED'],405);
$pdo=sc_pdo();sc_ensure_schema($pdo);$admin=sc_admin_auth($pdo);$id=(int)($_GET['id']??0);if($id<=0)sc_response(false,'Invalid ticket.',['code'=>'INVALID_TICKET'],422);$ticket=sc_get_ticket($pdo,$id);if(!$ticket)sc_response(false,'Ticket not found.',['code'=>'TICKET_NOT_FOUND'],404);
$access=$pdo->prepare('SELECT token_hash,access_type FROM support_ticket_access WHERE ticket_id=:id LIMIT 1');$access->execute([':id'=>$id]);$a=$access->fetch(PDO::FETCH_ASSOC);
$messages=sc_messages($pdo,$id);
try{$m=$pdo->prepare("UPDATE notifications SET is_read=1,read_at=CURRENT_TIMESTAMP WHERE user_id=:uid AND reference_type='support_ticket' AND reference_id=:rid AND is_read=0");$m->execute([':uid'=>(int)$admin['id'],':rid'=>$id]);}catch(Throwable $e){}
$ticket['id']=(int)$ticket['id'];$ticket['source_label']=sc_source_label((string)$ticket['source']);$ticket['status_label']=sc_status_label((string)$ticket['status']);$ticket['access_type']=$a['access_type']??($ticket['user_id']?'account':'guest');
sc_response(true,'Ticket loaded.',['ticket'=>$ticket,'messages'=>$messages,'feedback_link'=>null]);
