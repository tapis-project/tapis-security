package edu.utexas.tacc.tapis.jobs.model.submit;

import edu.utexas.tacc.tapis.apps.client.gen.model.AppFileInput;
import edu.utexas.tacc.tapis.apps.client.gen.model.FileInputModeEnum;
import edu.utexas.tacc.tapis.shared.uri.TapisLocalUrl;

public class JobFileInput 
{
    private String  name;
    private String  description;
    private Boolean autoMountLocal;
    private String  sourceUrl;
    private String  targetPath;
    private boolean optional = false;
    
    // Import an app input into a request input.
    public static JobFileInput importAppInput(AppFileInput appInput)
    {
        var reqInput = new JobFileInput();
        reqInput.setName(appInput.getName());
        reqInput.setDescription(appInput.getDescription());

        reqInput.setAutoMountLocal(appInput.getAutoMountLocal());
        
        reqInput.setSourceUrl(appInput.getSourceUrl());
        reqInput.setTargetPath(appInput.getTargetPath());
        
        // The default input mode is optional.
        if (appInput.getInputMode() == null ||
            appInput.getInputMode() == FileInputModeEnum.OPTIONAL)
            reqInput.setOptional(true);
        return reqInput;
    }
    
    public boolean isTapisLocal() {
        if (sourceUrl == null) return false;
        if (sourceUrl.startsWith(TapisLocalUrl.TAPISLOCAL_PROTOCOL_PREFIX)) return true;
        return false;
    }
    
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public Boolean getAutoMountLocal() {
        return autoMountLocal;
    }
    public void setAutoMountLocal(Boolean autoMountLocal) {
        this.autoMountLocal = autoMountLocal;
    }
    public String getSourceUrl() {
        return sourceUrl;
    }
    public void setSourceUrl(String sourceUrl) {
        this.sourceUrl = sourceUrl;
    }
    public String getTargetPath() {
        return targetPath;
    }
    public void setTargetPath(String targetPath) {
        this.targetPath = targetPath;
    }
    public boolean isOptional() {
        return optional;
    }
    public void setOptional(boolean optional) {
        this.optional = optional;
    }
}
