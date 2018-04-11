<!DOCTYPE html>
<html>
<head>
    <meta http-equiv=Content-Type content="text/html; charset=windows-1250">
    <title>Your Gastro-Booking</title>
</head>
<body bgcolor="#FFFFFF" lang=CSlink=#000080 vlink=#800080 text="#000000">

	<p>
		@lang('main.MAIL.REQUEST_UPDATE') <?= $order->cancellation  ?>  <?= $user->name ?><br/>
		<?= $order->persons?> @lang('main.MAIL.PERSONS') - <?= $orders_detail_count ?> @lang('main.MAIL.ITEMS') - @lang('main.MAIL.TOTAL_')<?= $orders_detail_total_price ?> <?= $currency ?> <br/>
		
		<?php foreach ($orders_detail_filtered as $orders_detail) {  
			if ($orders_detail->status == 3) { ?> <div style = "text-decoration: line-through"> <?php } ?>
			<?=  $orders_detail->x_number ?> @lang('main.MAIL.AVAILABLE SYMBOL')
			<?php 
            if ($orders_detail['requestMenu']->confirmed_name) {
                echo $orders_detail['requestMenu']->confirmed_name;
            }
            else{ echo $orders_detail['requestMenu']->name; }  ?>
		  	<?php if ( $orders_detail->price != '0.00' && $orders_detail->price != '') { ?> <?= $orders_detail->price ?><?= $currency ?> @lang('main.MAIL.AVAILABLE SYMBOL') <?= $orders_detail->x_number ?> <?php }
		  	if ($orders_detail->status == 3) { ?> </div> <?php } else{ echo "<br/> "; } ?>
		  	
		  	<?php
        } ?>


    gastro-booking.com
	</p>

</body></html>

