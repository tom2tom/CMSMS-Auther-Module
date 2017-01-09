{if !empty($message)}{$message}<br />{/if}
{$tab_headers}

{$start_data_tab}
{$startform1}
{if $icount > 0}
<div style="overflow:auto;">
  <table id="itemstable" class="leftwards pagetable">
    <thead><tr>
      <th>{$title_id}</th>
      <th>{$title_name}</th>
      <th>{$title_alias}</th>
{*if $own} <th>{$title_owner}</th>{/if*}
{if $bmod}<th class="pageicon {ldelim}sss:FALSE{rdelim}">&nbsp;</th>{/if}
			<th class="pageicon {ldelim}sss:FALSE{rdelim}">&nbsp;</th>
{if $mod}<th class="pageicon {ldelim}sss:FALSE{rdelim}">&nbsp;</th>{/if}
{if $del} <th class="pageicon {ldelim}sss:FALSE{rdelim}">&nbsp;</th>{/if}
      <th class="checkbox {ldelim}sss:FALSE{rdelim}" style="width:20px;">{if $icount > 1}{$selectall_items}{/if}</th>
    </tr></thead>
    <tbody>
 {foreach from=$items item=entry} {cycle values='row1,row2' assign='rowclass'}
    <tr class="{$rowclass}" onmouseover="this.className='{$rowclass}hover';" onmouseout="this.className='{$rowclass}';">
      <td>{$entry->id}</td>
      <td>{$entry->name}</td>
      <td>{$entry->alias}</td>
{*if $own} <td>{$entry->ownername}</td>{/if*}
{if $bmod}<td>{$entry->bedit}</td>{/if}
      <td>{$entry->see}</td>
{if $mod} <td>{$entry->edit}</td>{/if}
{if $del} <td class="bkrdel">{$entry->delete}</td>{/if}
      <td class="checkbox">{$entry->sel}</td>
    </tr>
 {/foreach}
    </tbody>
  </table>
</div>
{if !empty($hasnav3)}<div class="browsenav">{$first3}&nbsp;|&nbsp;{$prev3}&nbsp;&lt;&gt;&nbsp;{$next3}&nbsp;|&nbsp;{$last3}</div>{/if}
{else}
 <p class="pageinput">{$noitems}</p>
{/if}
<div id="itemacts" class="pageoptions" style="margin-top:1em;">
{if $add}{$additem}{/if}{if $del}span style="margin-left:12em;"{$delbtn1}</span>{/if}
</div>
{$endform}
{$end_tab}

{$start_settings_tab}
{if $set}
{$startform2}
<div style="margin:0 20px;overflow:auto;">
<p class="pagetext" style="font-weight:normal;">{$compulsory}</p>
{foreach from=$settings item=entry name=opts}
 <p class="pagetext">{$entry->title}:{if !empty($entry->must)} *{/if}</p>
 <div class="pageinput">{$entry->input}</div>
 {if !empty($entry->help)}<p class="pageinput">{$entry->help}</p>{/if}
{if !$smarty.foreach.opts.last}<br />{/if}
{/foreach}
</div>
<div class="pageinput" style="margin-top:1em;">{$submitbtn2} {$cancel}</div>
{$endform}
{else}
<p class="pageinput">{$nopermission}</p>
{/if}
{$end_tab}

{$tab_footers}
