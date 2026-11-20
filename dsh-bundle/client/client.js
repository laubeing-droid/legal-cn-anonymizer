window.__ModuleLoader__.load({id:`legal-cn-anonymizer`,factory:e=>{
// legal-cn-anonymizer DSH bundle — Client half（四件套之四：client panel）。
// wire 格式 = window.__ModuleLoader__.load({id, factory}) + {name, inject:['slots'], apply}
// （逐位对照生态真包 dsh-context@0.86.0 lib/client.js 形状；juscite 批4-01
// probes/fixtures/dsh-ui-five-slots 同构实证）。UI 只消费 ds-* 语义令牌。
let u=e("react");
const dict={
  'page.title':'隐私脱敏',
  'page.body':'文本脱敏/回填走 pii_scrub_text / pii_rehydrate_text 两件工具（legal-cn-anonymizer 正则层离线兜底）。',
  'page.notice':'诚实边界：身份证号/手机号/银行卡/邮箱等结构化实体可命中；姓名等 NER 实体不保证命中'
    +'（NER 权重不随包，姓名覆盖=REVIEW_REQUIRED 人工复核兜底）。脱敏结果使用前须人工确认；'
    +'本插件永不输出「已完全脱敏」类承诺。',
  'toolview.title':'脱敏结果（假名文本 + 映射句柄）'
};
function notice(){return u.createElement('div',{
  'data-slot-ui':'legal-cn-anonymizer-notice',
  style:{border:'1px solid var(--ds-border-muted)',borderRadius:'12px',padding:'8px 12px',fontSize:'12.5px',lineHeight:'1.6',color:'var(--ds-text-muted)',background:'var(--ds-surface-subtle)',whiteSpace:'pre-wrap'}
},dict['page.notice'])}
return {
  name: `legal-cn-anonymizer`,
  inject: [`slots`],
  apply: function(ctx){
    // 侧栏页：隐私脱敏说明页（工具入口 + 诚实边界）
    ctx.slots.inject(`sidebar.pages`,()=>ctx.slots.register(
      {name:`sidebar.pages`,key:`legal-cn-anonymizer`,id:`legal-cn-anonymizer-page`,order:40,label:()=>dict['page.title']},
      function(){return u.createElement('div',{'data-slot-ui':'legal-cn-anonymizer-page',style:{padding:'12px',fontSize:'13px',lineHeight:'1.7',color:'var(--ds-text)'}},
        u.createElement('div',{style:{fontWeight:600,marginBottom:'6px'}},dict['page.title']),
        u.createElement('div',{style:{marginBottom:'10px'}},dict['page.body']),
        notice())
      }
    ));
    // 工具卡视图：pii_scrub_text 的返回面（假名文本预览 + 映射句柄 + 边界提示）
    ctx.slots.inject(`tool.call.toolview`,()=>ctx.slots.register(
      {name:`tool.call.toolview`,key:`pii_scrub_text`,id:`legal-cn-anonymizer-toolview`,order:40},
      function(props){
        let value=props&&props.value;
        let text=typeof value==='object'&&value!==null?String(value.sanitizedText??''):'';
        let handle=typeof value==='object'&&value!==null?String(value.mapHandle??''):'';
        return u.createElement('div',{'data-slot-ui':'legal-cn-anonymizer-toolview',style:{border:'1px solid var(--ds-border)',borderRadius:'12px',padding:'8px 12px',fontSize:'12.5px',color:'var(--ds-text)',background:'var(--ds-surface-card)'}},
          u.createElement('div',{style:{fontWeight:600,marginBottom:'6px'}},dict['toolview.title']),
          u.createElement('div',{style:{whiteSpace:'pre-wrap',maxHeight:'240px',overflow:'auto'}},text),
          handle?u.createElement('div',{style:{marginTop:'6px',color:'var(--ds-text-muted)',fontSize:'12px'}},'mapHandle: '+handle):null,
          u.createElement('div',{style:{marginTop:'8px'}},notice()))
      }
    ));
  }
}
}});
